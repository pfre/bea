/*
Behaviour Analysis Scanner (bea)
bea.l
(C) 2012 Pedro Freire
	Free for research use.
	Contact phd@pedrofreire.com for other licensing.

Token scanner file.
Designed for GNU flex.

Includes functions to open/close PHP files,
as we need access to flex macros.


NOTES:

This Flex scanner uses a few non-trivial techniques to accomodate PHP language
features. For instance, variable names start with a dollar symbol ('$'), so
you can have variables that have the same name as PHP's keywords (e.g.: "$for").
Bu then, if one of those variables is actually a class property, even though
you declare it as "var $for;", you use it as "$obj->for", which is allowed by
PHP, but makes the usual concept of having a token for "->" and a token for
identifiers (named "labels" in PHP terminology) rather non-trivial.

Other than that, this file should be fairly straigh-forward to understand.

See bea.h for project notes.
*/


%option case-insensitive
%option 8bit
%option never-interactive
%option warn
%option yylineno
%option nostack
%option noyywrap

%option ecs nometa-ecs read
	/* command-line compression options:
		-Cemr:  88kb
		-Cer:   96kb
		-Cr:   136kb
		-Cfr:  360kb
		-CFr:  988kb
	   flex documentation states single table lookup per character
	   delay when going from -Cr to -Cer; difference in size between
	   both is 40kb or about 10 4kb clusters; since bea processes
	   small independent files, -Cr speedup should be unnoticeable.
	   use -Cer (ecs nometa-ecs read) */


%{

#define _GNU_SOURCE  /* for strcasestr() and strcasecmp() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "bea.h"
#include "bea.tab.h"

#define set_location()  {									\
	yylloc.filename = ( current_file >= 0 ? file_data[current_file].copy_filename : NULL );	\
	yylloc.include_level = current_file;							\
	yylloc.line = yylineno;									\
	}

#if YYDEBUG
#define  return1(r)		{                                   set_location(); return (r); }
#define  return2(r,r2)		{ token_pending=(r2); is_pending=1; set_location(); return (r); }
#define dreturn1(r)		{ if(opt.debug0) fprintf(stderr, "\n   TOKEN %s from \"%s\"\n",         #r,      yytext); return1(r);        }
#define dreturn2(r,r2)		{ if(opt.debug0) fprintf(stderr, "\n   TOKENS %s and %s from \"%s\"\n", #r, #r2, yytext); return2((r),(r2)); }
#define dBEGIN(s)		{ if(opt.debug0) fprintf(stderr, "\n   TOKEN %s from \"%s\"\n", #s, yytext); BEGIN( s ); }
#define d(tok)			{ if(opt.debug0) fprintf(stderr, "\n   TOKEN %s from \"%s\"\n", #tok, yytext); }
#define debug_string()		{ if(opt.debug5) debug_trace(s_value_string(&yylval.value), "", yylval.value.prone, '"'); }
#else
#define  return1(r)		{                                   set_location(); return (r); }
#define  return2(r,r2)		{ token_pending=(r2); is_pending=1; set_location(); return (r); }
#define dreturn1(r)		return1(r)
#define dreturn2(r,r2)		return2((r),(r2))
#define dBEGIN(s)		BEGIN( s )
#define d(tok)
#define debug_string()
#endif

char heredoc_label[ LEN_VSTRING+1 ] = "";

int current_file = -1;  // index into file_data[]; -1 = "no file"
struct	{
	char		copy_filename[ LEN_PATH+1 ];
	YY_BUFFER_STATE copy_YY_BUFFER_STATE;
	int		copy_yylineno;
	int             copy_YY_START;
	char            copy_namespace[ LEN_VSTRING+1 ];
	char            copy_class    [ LEN_VSTRING+1 ];
	}
	file_data[ MAX_NEST ];

int cond_pre_comment;
int token_pending, is_pending = 0;  // nothing pending

%}


%x COND_PHP
%x COND_PHP_LABEL
%x COND_COMMENT1
%x COND_COMMENT
%x COND_STRING1
%x COND_STRING
%x COND_BACKTICK
%x COND_HEREDOC
%x COND_NOWDOC


WS			[ \t\r\n]
LWS			[ \t]
EOL			(\r\n?|\n)
LABEL			[a-zA-Z_\x7F-\xFF][a-zA-Z0-9_\x7F-\xFF]*
NAMESPACE_LABEL		[\\]?{LABEL}([\\]{LABEL})*

%%


%{

// local yyflex() variables
int token1, token2;	// temporary tokens
char *pi;		// pointer to HEREDOC closing identifier (and dummy char*)
char *pie;		// pointer to HEREDOC closing identifier end
char sc;		// character after HEREDOC closing identifier (e.g.: ';')

if( is_pending )
	{
	is_pending = 0;  // nothing pending
	return token_pending;
	}

%}


"<?php"			BEGIN( COND_PHP );
"<?"[^x=]		BEGIN( COND_PHP );  unput( yytext[2] );  /* exclude <?xml, not <?eval(... */
"<?="			BEGIN( COND_PHP );  dreturn1( PHP_ECHO );
[^<]+			|
[<]			;

<*><<EOF>>		{
			flex_close_file();
			if( current_file < 0 )
				{
				if( YY_START == INITIAL )
					{ dreturn1(      YY_NULL ); }
				else
					{ dreturn2( ';', YY_NULL ); }
				}
			else
				{
				// closes the fake block started just before PHP_INCLUDE*
				if( YY_START == INITIAL )
					{ dreturn1(      '}' ); }
				else
					{ dreturn2( ';', '}' ); }
				}
			}

<COND_PHP,COND_PHP_LABEL>{
"?>"			BEGIN( INITIAL );  return1( ';' );
"//"|#			cond_pre_comment = YY_START;  BEGIN( COND_COMMENT1 );
"/*"			cond_pre_comment = YY_START;  BEGIN( COND_COMMENT  );
{WS}+			;
}

<COND_PHP>{
([0-9]+([.][0-9]*)?|[.][0-9]+)([Ee][+-]?[0-9]+)?  {
			s_value_set( &yylval.value, PRONE_NONE, TYPE_REAL, atof(yytext), NULL );
			dreturn1( CONST_NUMBER ); }
0[xX][0-9A-Fa-f]+	{
			s_value_set( &yylval.value, PRONE_NONE, TYPE_REAL, (double) strtol(yytext+2, &pi, 16), NULL );
			dreturn1( CONST_NUMBER ); }
true			{
			s_value_set( &yylval.value, PRONE_NONE, TYPE_REAL, 1.0,          NULL );
			dreturn1( CONST_NUMBER ); }
false			{
			s_value_set( &yylval.value, PRONE_NONE, TYPE_REAL, 0.0,          NULL );
			dreturn1( CONST_NUMBER ); }
null			{
			s_value_set( &yylval.value, PRONE_NONE, TYPE_NULL, 0.0,          NULL );
			dreturn1( CONST_NUMBER ); }

[']			{
			s_value_set( &yylval.value, PRONE_NONE, TYPE_STRING, 0, "" );
			BEGIN( COND_STRING1 ); }
b?["]			{
			s_value_set( &yylval.value, PRONE_NONE, TYPE_STRING, 0, "" );
			BEGIN( COND_STRING ); }
"<<<"{LWS}*{LABEL}{LWS}*{EOL}	{
			strncpy( heredoc_label, yytext+strspn(yytext, "< \t"), LEN_VSTRING );
			heredoc_label[ LEN_VSTRING ] = '\0';
			heredoc_label[ strcspn(heredoc_label, " \t\r\n") ] = '\0';
			s_value_set( &yylval.value, PRONE_NONE, TYPE_STRING, 0, "" );
			BEGIN( COND_HEREDOC ); }
"<<<"{LWS}*[']{LABEL}[']{LWS}*{EOL}	{
			strncpy( heredoc_label, yytext+strspn(yytext, "< \t'"), LEN_VSTRING );
			heredoc_label[ LEN_VSTRING ] = '\0';
			heredoc_label[ strcspn(heredoc_label, "' \t\r\n") ] = '\0';
			s_value_set( &yylval.value, PRONE_NONE, TYPE_STRING, 0, "" );
			BEGIN( COND_NOWDOC ); }
[`]			{
			s_value_set( &yylval.value, PRONE_NONE, TYPE_STRING, 0, "" );
			BEGIN( COND_BACKTICK ); }

"+="			|
"-="			|
"*="			|
"/="			|
"%="			|
".="			|
"|="			|
"&="			|
"^="			|
"<<="			|
">>="			|
"||="			|
"&&="			dreturn1( OP_ASSIGN );
"<<"			|
">>"			|
"||"			|
"&&"			|
and			|
or			|
xor			|
"=="			|
"==="			|
"!="			|
"!=="			|
"<>"			|
"<="			|
">="			|
instanceof		|
[*/%.|^<>]		dreturn1( OP_BINARY );
[!~]			dreturn1( OP_UNARY );
[+-]			dreturn1( OP_SIGN );  /* which is also OP_BIN */
"++"			|
"--"			dreturn1( OP_INCDEC );  /* which is also OP_UN, but not only */
[()\[\]{}=&$,;?:@]	dreturn1( *yytext );
"::"			dreturn1( OP_CLASS );
"->"			dreturn1( OP_OBJ );
"=>"			dreturn1( OP_ARRAY );

eval			dreturn1( EVAL );
(imap_)?mail		dreturn1( MAIL );

socket_connect		dreturn1( SOCKET_CONNECT );
fsockopen		dreturn1( FSOCKOPEN );
fopen			dreturn1( FOPEN );
fputs			|
fwrite			dreturn1( FWRITE );
file_put_contents	dreturn1( FILE_PUT_CONTENTS );

	/* casts can also be made to class names, so we just use non-terminal
	   "constant" in bison
	bool(ean)?		|
	int(eger)?		|
	float			|
	double			|
	real			|
	string			|
	binary			|
	object			dreturn1( PHP_TYPE );  // excludes "array" and "unset" */

array			dreturn1( ARRAY );
list			dreturn1( LIST );

base64_decode		|
imap_base64		dreturn1( PHP_OBFUSCATION );

import_request_variables |
extract			|
bcompiler_load_exe	|
bcompiler_load		|
bcompiler_read		|
apc_fetch		|
apc_load_constants	dreturn1( PHP_OBFUSCATED_INCLUDE );

passthru		|
system			|
shell_exec		|
popen			|
proc_open		|
exec			dreturn1( PHP_EXEC );

try			dreturn1( TRY            );
catch			dreturn1( CATCH          );
throw			dreturn1( THROW          );
echo			|
print			dreturn1( PHP_ECHO       );

if			dreturn1( IF             );
else			dreturn1( ELSE           );
elseif			dreturn2( ELSE, IF       );
endif			dreturn1( ENDIF          );
foreach			dreturn1( FOREACH        );
as			dreturn1( AS             );
endforeach		dreturn1( ENDFOREACH     );
for			dreturn1( FOR            );
endfor			dreturn1( ENDFOR         );
while			dreturn1( WHILE          );
endwhile		dreturn1( ENDWHILE       );
do			dreturn1( DO             );
switch			dreturn1( SWITCH         );
endswitch		dreturn1( ENDSWITCH      );
case			dreturn1( CASE           );
default			dreturn1( DEFAULT        );
break			dreturn1( BREAK          );
continue		dreturn1( CONTINUE       );
return			dreturn1( RETURN         );
goto			dreturn1( GOTO           );
declare			dreturn1( DECLARE        );
enddeclare		dreturn1( ENDDECLARE     );
define			dreturn1( DEFINE         );
include			|
require			dreturn2( '{', PHP_INCLUDE );
include_once		|
require_once		dreturn2( '{', PHP_INCLUDE_ONCE );
			/* TODO: Support __autoload() */

function		{ BEGIN( COND_PHP_LABEL );
			dreturn1( FUNCTION       ); }
global			dreturn1( GLOBAL         );

namespace		{ BEGIN( COND_PHP_LABEL );
			dreturn1( NAMESPACE      ); }
use			{ BEGIN( COND_PHP_LABEL );
			dreturn1( USE            ); }
class			|
interface		{ BEGIN( COND_PHP_LABEL );
			dreturn1( PHP_CLASS      ); }
extends			dreturn1( EXTENDS        );
implements		dreturn1( IMPLEMENTS     );
final			|
abstract		dreturn1( PHP_ABSTRACT   );
private			|
public			|
protected		dreturn1( PHP_VISIBILITY );
var			dreturn1( VAR            );
const			{ BEGIN( COND_PHP_LABEL );
			dreturn1( CONST          ); }
static			dreturn1( STATIC         );
new			{ BEGIN( COND_PHP_LABEL );  // will recover if not a label
			dreturn1( NEW            ); }
clone			dreturn1( CLONE          );

(?-i:[$]GLOBALS)	dreturn1( PHP_GLOBALS    );

("$"|"->"|"->$"|"::"|"::$")?{NAMESPACE_LABEL}  {
			/* we need to catch the leading "$", "->" and "::"
			   operators, in order to read "->echo" as a CONST_LABEL
			   rather than PHP_ECHO!
			   includes "self", "parent" and most namespace support */
			/* TODO: Better namespace and variable support */
			if( yytext[0] == '-' )
				{
				token1 = OP_OBJ;    d( OP_OBJ );
				yytext += 2;
				}
			else if( yytext[0] == ':' )
				{
				token1 = OP_CLASS;  d( OP_CLASS );
				yytext += 2;
				}
			else
				token1 = YY_NULL;

			if( yytext[0] == '$' )
				{
				// this way "$var" is not returned as '$' VAR
				token2 = PHP_VARIABLE;  d( PHP_VARIABLE );
				yytext++;
				}
			else
				{
				token2 = CONST_LABEL;   d( CONST_LABEL );
				}

			if( yytext[0] == '\\' )
				yytext++;
			if( strncmp(yytext, "namespace\\", 10) == 0 )
				{
				s_value_set( &yylval.value, PRONE_NONE, TYPE_STRING, 0, current_namespace );
				s_value_cat( &yylval.value, yytext+9 );
				}
			else
				s_value_set( &yylval.value, PRONE_NONE, TYPE_STRING, 0, yytext );
			if( strlen(yytext) > LEN_VSTRING  ||  strchr(yytext, '\\') != NULL )
				yylval.value.prone |= PRONE_EXTERNAL_MAYBE;
				// trap suspicious cases
			if( token1 != YY_NULL )
				return2( token1, token2 );
			return1( token2 );
			}

.			dreturn1( PHP_UNKNOWN );  /* bad token */
}

<COND_PHP_LABEL>{
{NAMESPACE_LABEL}	{
			if( yytext[0] == '\\' )
				yytext++;
			if( strncmp(yytext, "namespace\\", 10) == 0 )
				{
				s_value_set( &yylval.value, PRONE_NONE, TYPE_STRING, 0, current_namespace );
				s_value_cat( &yylval.value, yytext+9 );
				}
			else
				s_value_set( &yylval.value, PRONE_NONE, TYPE_STRING, 0, yytext );
			if( strlen(yytext) > LEN_VSTRING  ||  strchr(yytext, '\\') != NULL )
				yylval.value.prone |= PRONE_EXTERNAL_MAYBE;
				// trap suspicious cases
			BEGIN( COND_PHP );
			dreturn1( CONST_LABEL ); }
.|\r|\n			{
			unput( *yytext );
			BEGIN( COND_PHP ); }
}


<COND_COMMENT1>{
"?>"			BEGIN( INITIAL );  return1( ';' );
[\r\n]			BEGIN( cond_pre_comment );
[?]|[^?\r\n]+		;
}

<COND_COMMENT>{
	/* ?> is actually not recognised in multi-line comments or strings!
	"?>"		BEGIN( INITIAL );  return1( ';' ); */
"*/"			BEGIN( cond_pre_comment );
[?*]|[^?*]+		;
}

<COND_STRING1>{
[']			{
			yylval.value.prone |= str_prone( yylval.value.u.string );
			BEGIN( COND_PHP );
			debug_string();
			dreturn1( CONST_STRING ); }
\\['\\]			s_value_cat( &yylval.value, yytext+1 );
[^\\']+|\\[^'\\]	s_value_cat( &yylval.value, yytext   );
}

<COND_STRING>{
["]			{
			yylval.value.prone |= str_prone( yylval.value.u.string );
			BEGIN( COND_PHP );
			debug_string();
			dreturn1( CONST_STRING ); }
[^\\${"]+|[${]		s_value_cat( &yylval.value, yytext );  /* including \r\n */
}

<COND_BACKTICK>{
[`]			{
			yylval.value.prone |= str_prone( yylval.value.u.string );
			BEGIN( COND_PHP );
			debug_string();
			dreturn1( CONST_BACKTICK ); }
[^\\${`]+|[${]		s_value_cat( &yylval.value, yytext );  /* including \r\n */
}

<COND_HEREDOC,COND_NOWDOC>{
{EOL}{LABEL}[;]?{EOL}	{
			pi = yytext + strspn( yytext, "\r\n" );
			pie = pi + strcspn( pi, ";\r\n" );
			sc = *pie;
			*pie = '\0';
			if( strcmp(pi, heredoc_label) == 0 )
				{
				yylval.value.prone |= str_prone( yylval.value.u.string );
				BEGIN(COND_PHP);
				debug_string();
				if( sc == ';' )  { dreturn2( CONST_STRING, ';' ); }
				else             { dreturn1( CONST_STRING      ); }
				}
			*pie = sc;
			// this line may be last of HEREDOC/NOWDOC:
			// unput() the last EOL char so we may detect it later on
			unput( yytext[yyleng-1] );
			yytext[ yyleng-1 ] = '\0';
			s_value_cat( &yylval.value, yytext );
			}
[\r\n]			s_value_cat( &yylval.value, yytext );
}
<COND_HEREDOC>[^\\${\r\n]+|[${]  s_value_cat( &yylval.value, yytext );
<COND_NOWDOC>[^\r\n]+            s_value_cat( &yylval.value, yytext );

<COND_STRING,COND_BACKTICK,COND_HEREDOC>{
	/* ?> is actually not recognised in multi-line comments or strings!
	"?>"		BEGIN( INITIAL );  return1( ';' ); */
	/* TODO: Support "namespace\" prefix */
[$]{NAMESPACE_LABEL}	{
			s_value_cat( &yylval.value, yytext );
			yylval.value.prone |= var_prone(yytext, VAR_IS_CONTEXT); }
[$][{]{NAMESPACE_LABEL}	|
[{][$]{NAMESPACE_LABEL}	{
			s_value_cat( &yylval.value, yytext );
			yytext[1] = '$';
			yylval.value.prone |= var_prone(yytext+1, VAR_IS_CONTEXT); }
(?-i:[$]GLOBALS\[{NAMESPACE_LABEL}\])  {
			s_value_cat( &yylval.value, yytext );
			yytext[yyleng-1] = '\0';
			yytext[8] = '$';
			yylval.value.prone |= var_prone(yytext+8, VAR_IS_GLOBAL); }
(?-i:[$][{]GLOBALS\['?{NAMESPACE_LABEL}'?\])  |
(?-i:[{][$]GLOBALS\['?{NAMESPACE_LABEL}'?\])  {
			int pos;
			s_value_cat( &yylval.value, yytext );
			pos = ( yytext[10] == '\'' ? 10 : 9 );
			yytext[yyleng-1-(pos-9)] = '\0';
			yytext[pos] = '$';
			yylval.value.prone |= var_prone(yytext+pos, VAR_IS_GLOBAL); }
\\[xX]([2-6][0-9a-fA-F]|7[0-9a-eA-E])  |
\\(0?[4-7][0-7]|1[0-6][0-7]|17[0-6])   {
			s_value_cat( &yylval.value, unescape_str(yytext) );
			yylval.value.prone |= PRONE_OBFUSCATED;
			/* these are printable ASCII characters */ }
\\[xX][0-9a-fA-F]{1,2}	|
\\[0-7]{1,3}		|
\\[^xX0-7]		s_value_cat( &yylval.value, unescape_str(yytext) );
}


%%


/* Called when the file is first opened, and when a file is being included.
   "once" is true (!=0) if no file should be opened if it has already been
   previously opened. This value is ignored when opening the first file.
   Saves previous file's yylex() state.
*/
void flex_open_file( const char *file, int once )
{
	static char filenames_opened[ MAX_OPENED_FILES ][ LEN_VSTRING+1 ];
	static int filenames_opened_num = 0;
	char include_path[ LEN_VSTRING+1 ];
	char path[ LEN_PATH+1 ];
	char *p, *p2;
	int i, len, err_long;
	FILE *fp;

	assert( file != NULL  &&  file[0] != '\0' );

	if( current_file >= MAX_NEST-1 )
		{
		if( opt.warn )
			fprintf( stderr, "Warning: maximum include nesting reached (include loop?). Ignoring new includes.\n" );
		token_pending = '}';  // pretend we closed the include()'s fake block
		is_pending = 1;
		return;
		}

	if( current_file >= 0 )
		{
		// this is a file being included:
		// search through the include_path

		assert( is_pending == 0 );
			// we must have found "{ PHP_INCLUDE ( expr )" so far
			// for an include file to be opened, so there should
			// be no pending tokens
#if YYDEBUG
		if( opt.debug1 )
			fprintf( stderr, "include(\"%s\");\n", file );
#endif

		strcpy( include_path, diropt.include_path );
			// also repeat this search using opt.include_path,
			// just in case Apache isn't reading .htaccess?
		fp = NULL;
		err_long = 0;
		for( p = strtok(include_path, ":;");  p != NULL;  p = strtok(NULL, ":;") )
			{
			if( p[0] != '/' )
				{
				// based on the directory of the main PHP file
				p2 = strrchr( file_data[0].copy_filename, '/' );
				len = ( p2 == NULL ? 0 : p2-file_data[0].copy_filename );
				if( len + 1 + strlen(p) > array_size(path)-1 )
					{
					err_long = 1;
					continue;
					}
				strncpy( path, file_data[0].copy_filename, len );
				path[len] = '/';
				strcpy ( path+len+1, p );
				}
			else
				strcpy( path, p );

			len = strlen( path );
			if( path[len-1] != '/' )
				strcpy( path+len++, "/" );
			if( len + strlen(file) > array_size(path)-1 )
				{
				err_long = 1;
				continue;
				}
			strcpy( path+len, file );

			for( i = 0;  i < filenames_opened_num;  i++ )
				{
				if( strncmp(filenames_opened[i], path, array_size(filenames_opened[0])) == 0 )
					break;
				}
			if( i < filenames_opened_num )
				{
				token_pending = '}';  // pretend we closed the include()'s fake block
				is_pending = 1;
				return;  // already previously opened
				}

			fp = fopen( path, "r" );
			if( fp != NULL )
				{
				file = path;
				break;
				}
			}
		if( err_long )
			{
#if YYDEBUG
			if( opt.warn  ||  opt.debug1 )
#else
			if( opt.warn )
#endif
				fprintf( stderr, "Warning: Path too long while searching for include file. Ignoring.\n" );
			}
		if( fp == NULL )
			{
#if YYDEBUG
			if( opt.warn  ||  opt.debug1 )
#else
			if( opt.warn )
#endif
				fprintf( stderr, "Warning: Could not find include file \"%s\". Ignoring.\n", file );
			token_pending = '}';  // pretend we closed the include()'s fake block
			is_pending = 1;
			return;
			}
		}
	else
		{
#if YYDEBUG
		if( opt.debug1 )
			fprintf( stderr, "opening main PHP file \"%s\"\n", file );
#endif
		filenames_opened_num = 0;
		fp = fopen( file, "r" );
		if( fp == NULL )
			{
#if YYDEBUG
			if( opt.warn  ||  opt.debug1 )
#else
			if( opt.warn )
#endif
				fprintf( stderr, "Error: Could not open requested file \"%s\".\n", file );
			exit( EXIT_ERROR );
			}
		}

	if( filenames_opened_num < MAX_OPENED_FILES-1 )
		{
		strncpy( filenames_opened[filenames_opened_num], file, array_size(filenames_opened[0]) );
		filenames_opened[filenames_opened_num][ array_size(filenames_opened[0])-1 ] = '\0';
		filenames_opened_num++;
		}
#if YYDEBUG
	else if( opt.warn  ||  opt.debug1 )
#else
	else if( opt.warn )
#endif
		fprintf( stderr, "Warning: Exhausted opened file buffer. Next include_once() and\n"
		                 "require_once() will behave like include() or require().\n" );

	if( current_file >= 0 )
		{
		file_data[current_file].copy_YY_BUFFER_STATE = YY_CURRENT_BUFFER;
		file_data[current_file].copy_yylineno = yylineno;
		file_data[current_file].copy_YY_START = YY_START;
		strcpy( file_data[current_file].copy_namespace, current_namespace );
		strcpy( file_data[current_file].copy_class,     current_class     );
		class_end();
		namespace_end();
		}
	else
		is_pending = 0;  // nothing pending

	current_file++;
	strncpy( file_data[current_file].copy_filename, file, array_size(file_data[0].copy_filename) );
	file_data[current_file].copy_filename[ array_size(file_data[0].copy_filename)-1 ] = '\0';
	yy_switch_to_buffer( yy_create_buffer(fp, YY_BUF_SIZE) );
	yylineno = 1;
	BEGIN( INITIAL );
	namespace_start( "" );
	class_start    ( "" );
}


/* Called when EOF is found (e.g.: an included file has been parsed).
   Restores yylex() state to previous file.
*/
void flex_close_file( void )
{
	assert( current_file >= 0 );
	class_end();
	namespace_end();
	fclose( yyin );
	current_file--;
	if( current_file >= 0 )
		{
#if YYDEBUG
		if( opt.debug1 )
			fprintf( stderr, "closing included file\n" );
#endif
		yy_delete_buffer( YY_CURRENT_BUFFER );
		yy_switch_to_buffer( file_data[current_file].copy_YY_BUFFER_STATE );
		yylineno = file_data[current_file].copy_yylineno;
		BEGIN( file_data[current_file].copy_YY_START );
		namespace_start( file_data[current_file].copy_namespace );
		class_start    ( file_data[current_file].copy_class );
		/* TODO: Verify if this is PHP semantics, as it seems you
		         leave a class if you do an include() in it. */
		}
	else
		{
		is_pending = 0;  // nothing pending
#if YYDEBUG
		if( opt.debug1 )
			fprintf( stderr, "closing main PHP file\n" );
#endif
		/* don't do this as it would crash, if used;
		   instead just allow the already closed descriptor to be used
		yyin = NULL;
		*/
		BEGIN( INITIAL );
		namespace_start( "" );
		class_start    ( "" );
		}
}


/* Writes to fp the file nesting path that leads to a found error
*/
void flex_display_file_nest( FILE *fp, int line )
{
	int i;

	assert( fp != NULL );

	if( current_file < 0 )
		{
		fprintf( fp, "\tin line %i of file\n",
			line );
		}
	else
		{
		fprintf( fp, "\tin line %i of file \"%s\"\n",
			line,
			file_data[current_file].copy_filename );

		for( i = current_file-1;  i >= 0;  i-- )
			{
			fprintf( fp, "\tincluded in line %i of file \"%s\"\n",
				file_data[i].copy_yylineno,
				file_data[i].copy_filename );
			}
		}
}


/* Resets included file stack
*/
void flex_reset_files( void )
{
	int i;

	for( i = current_file;  i >= 0;  i-- )
		flex_close_file();
}
