/*
Behaviour Analysis Scanner (bea)
bea-lib.c
(C) 2012 Pedro Freire
	Free for research use.
	Contact phd@pedrofreire.com for other licensing.

Note: avoid naming this file "bea.c" as GNU make sometimes tries to create it
automatically from bea.y, destroying any previous bea.c.

Functions.

NOTES:
See bea.h for project notes.
*/


#define _GNU_SOURCE  /* for strcasestr() and strcasecmp() */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <float.h>
#include <math.h>
#include <errno.h>
#include <assert.h>

#include <sys/stat.h>
#include <dirent.h>

#include "bea.h"
#include "bea.tab.h"


/* unused until we build a full parse tree:
   Semantic execution codes.
   "TOS" means "Top Of Stack", "TOS1", means "Top Of Stack + 1", etc.
+/
#define RUN_PUSH_VALUE		 1
#define RUN_OP_VAR		 2  // replace TOS by variable with name in TOS
#define RUN_OP_OBJ		 3  // replace TOS and TOS1 with variable with name in TOS from object with name is TOS1
#define RUN_OP_METHOD		 4  // replace TOS and TOS1 with result of function with name in TOS from object with name is TOS1
#define RUN_OP_BINARY_NUMERIC	 5
#define RUN_OP_UNARY_NUMERIC	 6
#define RUN_OP_CONCAT		 7
...
*/


/* Global bea options
*/
struct s_opt opt = {
                   { ".php", ".php5", ".php4", ".php3", ".phtml", ".phtm" },
                   ".",
                   0, 0,
#if YYDEBUG
                   0, 0, 0, 0, 0, 0, 0,
#endif
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                   };


/* Status of current file being processed
*/
struct s_dir_opt diropt = {};
//
char current_namespace[ LEN_VSTRING+1 ] = "";
char current_class    [ LEN_VSTRING+1 ] = "";
//
struct s_var *vars_global = NULL;
struct s_var **context_vars = NULL;
int context_vars_index = 0;
//
struct s_function *context_fn[ MAX_NEST ] = {};  // item inside "functions" list; [0] and [1] unused
int context_index = 1;  // 1 means global, "no function being defined"
//
struct s_function *functions = NULL;
struct s_var *arg_list = NULL;

/* If we ever found the token PHP_OBFUSCATED_INCLUDE, and where.
*/
int obfuscated_include_found = 0;  // false
struct s_file_location obfuscated_include_yylloc;


// ==========================================================================
// #### main(), directory, file and reset ###################################
// ==========================================================================


int main( int argc, char *argv[] )
{
	int argi, argi_next, i, ex, ex1;
	char *p;
	struct stat filename_stat;

	/* parse options */
#if YYDEBUG
	yydebug = 0;        // no debugging
	yy_flex_debug = 0;  // no debugging (req)
#endif
	ex = 0;  // no errors forcing exit
	for( argi = 1, argi_next = 2;
	     argi < argc  &&  argv[argi][0] == '-';
	     argi = argi_next++ )
		{
		for( i = 1;  i < strlen(argv[argi]);  i++ )
			{
			switch( argv[argi][i] )
				{
				case 'l':	opt.list = 1;
						break;
				case 'c':	opt.clist = 1;
						break;
				case 'r':	opt.recursive = 1;
						break;
				case 'w':	opt.warn = 1;
						break;
#if YYDEBUG
				case 'f':	yy_flex_debug = 1;  // activate debugging
						break;
				case 'b':	yydebug = 1;        // activate debugging (req)
						break;
				case '0':	opt.debug0 = 1;
						break;
				case '1':	opt.debug1 = 1;
						break;
				case '2':	opt.debug2 = 1;
						break;
				case '3':	opt.debug3 = 1;
						break;
				case '4':	opt.debug4 = 1;
						break;
				case '5':	opt.debug5 = 1;
						break;
				case '6':	opt.debug6 = 1;
						break;
#endif
				case 'i':	break;  // handled bellow
				case 'x':	break;  // handled bellow
				case 'q':	opt.quiet_if_ok = 1;
						break;
				case 'Q':	opt.quiet_if_ok = 1;
						opt.quiet_if_parse_error = 1;
						break;
				case 'E':	opt.disable_eval = 1;
						break;
				case 'X':	opt.disable_exec = 1;
						break;
				case 'M':	opt.disable_mail = 1;
						break;
				case 'S':	opt.disable_socket = 1;
						break;
				case 'W':	opt.disable_fwrite = 1;
						break;
				case 'O':	opt.disable_obfuscation = 1;
						break;
				case 'h':	opt.help = 1;
						break;
				default:	fprintf( stderr, "Unknown option: -%c\nUse -h for help.\n", argv[argi][i] );
						ex = 1;  // error
						break;
				}
			if( argv[argi][i] == 'i' )
				{
				// outside the switch() so we can break out of the for()
				if( argi_next >= argc )
					{
					fprintf( stderr, "Missing include path.\n" );
					ex = 1;  // error
					break;
					}
				if( strlen(argv[argi_next]) > LEN_VSTRING )
					{
					fprintf( stderr, "Include path too long: maximum length is %i characters.\n", LEN_VSTRING );
					ex = 1;  // error
					break;
					}
				strcpy( opt.include_path, argv[argi_next] );
				argi_next++;
				}
			if( argv[argi][i] == 'x' )
				{
				// outside the switch() so we can break out of the for()
				if( argi_next >= argc )
					{
					fprintf( stderr, "Missing file extension list.\n" );
					ex = 1;  // error
					break;
					}
				for( i = 0, p = strtok(argv[argi_next], ",;/ \t");
				     i < MAX_EXTENSIONS  &&  p != NULL;
				     i++, p = strtok(NULL, ",;/ \t") )
					{
					if( p[0] == '.' )
						p++;
					if( strlen(p) <= 0 )
						continue;
					if( strlen(p) >= LEN_EXTENSION )
						{
						fprintf( stderr, "PHP extension \".%s\" too long:\nmaximum length is %i characters, including the leading dot.\n", p, LEN_EXTENSION );
						ex = 1;  // error
						break;
						}
					opt.extensions[i][0] = '.';
					strcpy( opt.extensions[i]+1, p );
					}
				if( i >= MAX_EXTENSIONS  &&  p != NULL )
					{
					fprintf( stderr, "Too many PHP extensions specified: maximum is %i.\n", MAX_EXTENSIONS );
					ex = 1;  // error
					}
				while( i < MAX_EXTENSIONS )
					opt.extensions[i++][0] = '\0';
				argi_next++;
				}
			}
		}
	if( !opt.help  &&  argi >= argc )
		{
		fprintf( stderr, "Missing filename.\n"
		                 "Try \"%s -h\" for help.\n", argv[0] );
		ex = 1;  // error
		}
	if( opt.help )
		{
		printf(	"Usage: %s [options] filename(s)\n"
			"where [options] can be:\n"
			"-l	Display (list) only the file name if a virus found (implies -q)\n"
			"-c	Display a character, a space and then the file name of each parsed file\n"
			"-r	Filename is a directory to be traversed recursively\n"
			"-w	Display parsing errors and warnings\n"
#if YYDEBUG
			"-f	Display debug traces for flex (token detection)\n"
			"-b	Display debug traces for bison (grammar parsing)\n"
			"-0	Display debug traces for flex returned tokens\n"
			"-1	Display debug traces for file opening/inclusion\n"
			"-2	Display debug traces for class definitions and usage\n"
			"-3	Display debug traces for function definitions and calls\n"
			"-4	Display debug traces for variable assignments\n"
			"-5	Display debug traces for constants\n"
			"-6	Display debug str_prone() results\n"
#endif
			"-i	The next argument is PHP's include_path\n"
			"-x	The next argument is a comma-separated list of PHP file extensions to scan\n"
			"	(default: is \".php,.php5,.php4,.php3,.phtml,.phtm\")\n"
			"-q	Do not display anything if the file has no virus\n"
			"-Q	Same as -q, but also skip displaying files with parsing errors\n"
			"-E	Disable scanning for suspicious eval()\n"
			"-X	Disable scanning for external program execution with external provided data\n"
			"-M	Disable scanning for mail() to external provided address\n"
			"-S	Disable scanning for socket connections to external provided address\n"
			"-W	Disable scanning for suspicious open/write with external provided data\n"
			"-O	Disable scanning for suspicious variable/code obfuscation\n"
			"-h	Display this help\n"
			"\n"
			"The first argument that is not an option marks the start of filenames.\n"
			"No options are interpreted after such argument.\n"
			"Note that each filename can refer to a directory, in which case all\n"
			"files inside are scanned. PHP 2 and PHP 1 files (.phtml) are also scanned\n"
			"even though their syntax is not supported.\n"
#if YYDEBUG
			"If you set -6 without setting -5, files will not be scanned, but will instead be\n"
			"evaluated by str_prone() in full, to determine obfuscation statistics."
#endif
			"\n"
			"If you use -c, the character will state the parse status, and can be:\n"
			"	-  nothing found\n"
			"	?  error parsing the file\n"
			"	E  found suspicious eval()\n"
			"	X  found external program execution\n"
			"	M  found mail() to external provided address\n"
			"	S  found socket connections to external provided address\n"
			"	W  found suspicious open/write to file with external provided data\n"
			"	O  found suspicious variable/code obfuscation\n"
			"\n"
			"Return values as grep: 0 if virus is found, 1 otherwise. Returns 2 on error.\n",
			argv[0] );
		ex = 1;  // error
		}

	if( ex )
		return EXIT_SUCCESS;

	/* start parsing filename(s) */

	ex = EXIT_NOT_FOUND;
	for( ;  argi < argc;  argi++ )
		{
		if( stat(argv[argi], &filename_stat) != 0 )
			{
			/* actually, always show
			if( opt.warn )
			*/
				fprintf( stderr, "Error: Could not determine if name is directory or file: does it exist?\n\t\"%s\"\n", argv[argi] );
			exit( EXIT_ERROR );
			}
		if( S_ISDIR(filename_stat.st_mode) )
			ex1 = yyparse_dir( argv[argi], (struct s_dir_opt*) &opt );
		else if( S_ISREG(filename_stat.st_mode) )
			ex1 = yyparse_file( argv[argi], (struct s_dir_opt*) &opt );
		else
			ex1 = EXIT_NOT_FOUND;

		if( ex != EXIT_ERROR  &&  (ex1 == EXIT_ERROR || ex1 == EXIT_FOUND) )
			ex = ex1;
		}
	return ex;
}


/* Parses a single directory and returns one of EXIT_*
   indicating parse result.
*/
int yyparse_dir( const char *dirname, const struct s_dir_opt *prev_pdiropt )
{
	/* struct s_dir_opt diropt;  // currently unused */
	const struct s_dir_opt *pdiropt;
	int len_d, len_n, i, ex, ex1;
	DIR *dp;
	struct dirent *pde;
	char path[ LEN_PATH+1 ];

	assert( dirname      != NULL );
	assert( prev_pdiropt != NULL );

#if YYDEBUG
	if( opt.debug1 )
		fprintf( stderr, "Scanning (sub)directory \"%s\"...\n", dirname );
#endif

	pdiropt = prev_pdiropt;
		/* TODO: Scan directory for .htaccess and read any
		   directives changing PHP's include path, or file
		   extensions responding to PHP */

	ex = EXIT_NOT_FOUND;
	len_d = strlen( dirname );
	if( len_d > LEN_PATH-2 )  // -1 for "/" and -1 for a short name
		{
		/* actually, always show
		#if YYDEBUG
		if( opt.warn  ||  opt.debug1 )
		#else
		if( opt.warn )
		#endif
		*/
			fprintf( stderr, "Error: Requested directory is nested too deep, and I cannot store its full path:\n\t\"%s\"\n", dirname );
		exit( EXIT_ERROR );
		}

	dp = opendir( dirname );
	if( dp == NULL )
		{
		/* actually, always show
		#if YYDEBUG
		if( opt.warn  ||  opt.debug1 )
		#else
		if( opt.warn )
		#endif
		*/
			fprintf( stderr, "Error: Could not open requested directory \"%s\".\n", dirname );
		exit( EXIT_ERROR );
		}
	strcpy( path, dirname );
	if( path[len_d-1] != '/' )
		strcpy( path+len_d++, "/" );
	while( (pde = readdir(dp)) != NULL )
		{
#if YYDEBUG
		if( opt.debug1  &&  opt.warn )
			fprintf( stderr, "Found directory entry named \"%s\".\n", pde->d_name );
#endif
		if( pde->d_type == DT_DIR  &&  opt.recursive  &&
		    strcmp(pde->d_name, "." ) != 0  &&
		    strcmp(pde->d_name, "..") != 0 )
			{
			if( strlen(pde->d_name) > LEN_PATH-len_d )
				{
				// this also traps excessive nesting
				/* actually, always show
				#if YYDEBUG
				if( opt.warn  ||  opt.debug1 )
				#else
				if( opt.warn )
				#endif
				*/
					fprintf( stderr, "Error: Requested directory is nested too deep, and I cannot store its full path:\n\tDirectory \"%s\", file \"%s\".\n", dirname, pde->d_name );
				exit( EXIT_ERROR );
				}
			strcpy( path+len_d, pde->d_name );
			ex1 = yyparse_dir( path, pdiropt );
			if( ex != EXIT_ERROR  &&  (ex1 == EXIT_ERROR || ex1 == EXIT_FOUND) )
				ex = ex1;
#if YYDEBUG
			if( opt.debug1 )
				fprintf( stderr, "Returning to scan of (sub)directory \"%s\"...\n", dirname );
#endif
			}
		else if( pde->d_type == DT_REG )
			{
			len_n = strlen( pde->d_name );
			for( i = 0;  i < MAX_EXTENSIONS;  i++ )
				{
				if( pdiropt->extensions[i][0] == '\0' )
					break;
				if( strcmp(pdiropt->extensions[i], pde->d_name + len_n - strlen(pdiropt->extensions[i])) == 0 )
					{
					strcpy( path+len_d, pde->d_name );
					ex1 = yyparse_file( path, pdiropt );
					if( ex != EXIT_ERROR  &&  (ex1 == EXIT_ERROR || ex1 == EXIT_FOUND) )
						ex = ex1;
					break;
					}
				}
			}
		}
	closedir( dp );
#if YYDEBUG
	if( opt.debug1 )
		fprintf( stderr, "Finished scan of (sub)directory \"%s\".\n", dirname );
#endif
	return ex;
}


/* Parses a single file and returns one of EXIT_*
   indicating parse result.
*/
int yyparse_file( const char *filename, const struct s_dir_opt *pdiropt )
{
	int php;
	char c, *p;
#if YYDEBUG
	FILE *fp;
	struct stat filename_stat;
#endif

	assert( filename != NULL );
	assert( pdiropt  != NULL );

#if YYDEBUG
	if( opt.debug6  &&  !opt.debug5 )
		{
		if( stat(filename, &filename_stat) != 0  ||  !S_ISREG(filename_stat.st_mode) )
			{
			/* actually, always show
			if( opt.warn )
			*/
				fprintf( stderr, "Error: Could not open file for reading: does it exist?\n\t\"%s\"\n", filename );
			exit( EXIT_ERROR );
			}
		p = malloc( filename_stat.st_size+1 );
		fp = fopen( filename, "r" );
		if( p == NULL  ||  fp == NULL  ||  fread(p, filename_stat.st_size, 1, fp) != 1 )
			{
			/* actually, always show
			if( opt.warn )
			*/
				fprintf( stderr, "Could not read file into memory (out of memory or error reading)\n\t\"%s\"\n", filename );
			exit( EXIT_ERROR );
			}
		fclose( fp );
		p[ filename_stat.st_size ] = '\0';
		fprintf( stderr, "String statistics for file \"%s\"...\n", filename );
		str_prone( p );
		free( p );
		return EXIT_NOT_FOUND;
		}
	if( opt.debug1 )
		fprintf( stderr, "Preparing to parse file \"%s\"...\n", filename );
#endif
	diropt = *pdiropt;

	flex_reset_files();  // close any and all open files
	flex_open_file( filename, 0 );

	yyparse_reset();
	php = yyparse();
	php = fn_call_check( php );
	if( php == PARSE_OK  &&  obfuscated_include_found  &&  !opt.disable_obfuscation )
		{
		yylloc = obfuscated_include_yylloc;  // report error location correctly
		php = PARSE_OBFUSCATION;
		}

	if( opt.list )
		{
		switch( php )
			{
			case PARSE_OK:     /* fall through */
			case PARSE_ERROR:  /* fall through */
			case PARSE_ERROR_MEM:
				break;  /* not found */
		//	case PARSE_EVAL:
		//	case PARSE_EXEC:
		//	case PARSE_MAIL:
		//	case PARSE_SOCKET:
		//	case PARSE_FWRITE:
		//	case PARSE_OBFUSCATION:
			default:	
				puts( filename );
			}
		}
	else
		{
		switch( php )
			{
			case PARSE_OK:
				p = "No virus found.";
				c = '-';
				if( opt.quiet_if_ok )
					c = '\0';
				break;
			case PARSE_ERROR:     /* fall through */
			case PARSE_ERROR_MEM:
				p = "Error parsing file";
				c = '?';
				if( opt.quiet_if_parse_error )
					c = '\0';
				break;
			case PARSE_EVAL:
				p = "Found suspicious eval()";
				c = 'E';
				break;
			case PARSE_EXEC:
				p = "Found external program execution with external provided data";
				c = 'X';
				break;
			case PARSE_MAIL:
				p = "Found mail() to external provided address";
				c = 'M';
				break;
			case PARSE_SOCKET:
				p = "Found socket connections to external provided address";
				c = 'S';
				break;
			case PARSE_FWRITE:
				p = "Found suspicious open/write to file with external provided data";
				c = 'W';
				break;
			case PARSE_OBFUSCATION:
				p = "Found suspicious variable/code obfuscation";
				c = 'O';
				break;
			default:
				assert( 0 );
			}
		if( c != '\0' )
			{
			if( opt.clist )
				printf( "%c %s\n", c, filename );
			else
				{
				printf( "%s\n\t%s\n", filename, p );
				if( php != PARSE_OK )
					flex_display_file_nest( stdout, yylloc.line );
				}
			}
		}

	/* done by flex's <<EOF>>: flex_close_file(); */

#if YYDEBUG
	if( opt.debug1 )
		fprintf( stderr, "Finished parsing file \"%s\".\n", filename );
#endif

	/* select a return value based on grep return values */
	switch( php )
		{
		case PARSE_OK:		return EXIT_NOT_FOUND;
		case PARSE_ERROR:	/* fall through */
		case PARSE_ERROR_MEM:	return EXIT_ERROR;
		default:		return EXIT_FOUND;
		}
}


/* Resets semantic analysis context variables before a new file is parsed.
*/
void yyparse_reset( void )
{
	struct s_var *p, *p2;

	// delete entire variable arrays.
	// NEVER delete vars_global BEFORE vars_local!
	arg_list_reset();

	// delete "functions" and its local function call lists
	fn_call_check( PARSE_OK );

	// delete "context_fn[]" and its local variables
	while( context_index >= CONTEXT_LOCAL0 )
		function_end( 0 );

	// delete "vars_global"
	p = vars_global;
	while( p != NULL )
		{
		p2 = p->next[CONTEXT_GLOBAL];
		free( p );
		p = p2;
		}
	vars_global = NULL;

	context_vars = &vars_global;
	context_index = CONTEXT_GLOBAL;

	obfuscated_include_found = 0;  // false

	var_assign_null( "$_REQUEST",		PRONE_EXTERNAL, VAR_IS_SUPERGLOBAL );
	var_assign_null( "$_GET",		PRONE_EXTERNAL, VAR_IS_SUPERGLOBAL );
	var_assign_null( "$_POST",		PRONE_EXTERNAL, VAR_IS_SUPERGLOBAL );
	var_assign_null( "$_FILES",		PRONE_EXTERNAL, VAR_IS_SUPERGLOBAL );
	var_assign_null( "$_COOKIE",		PRONE_EXTERNAL, VAR_IS_SUPERGLOBAL );
	var_assign_null( "$HTTP_RAW_POST_DATA",	PRONE_EXTERNAL, VAR_IS_GLOBAL );
	var_assign_null( "$HTTP_GET_VARS",	PRONE_EXTERNAL, VAR_IS_GLOBAL );
	var_assign_null( "$HTTP_POST_VARS",	PRONE_EXTERNAL, VAR_IS_GLOBAL );
	var_assign_null( "$HTTP_POST_FILES",	PRONE_EXTERNAL, VAR_IS_GLOBAL );
	var_assign_null( "$HTTP_COOKIE_VARS",	PRONE_EXTERNAL, VAR_IS_GLOBAL );
	var_assign_null( "$argc",		PRONE_EXTERNAL, VAR_IS_GLOBAL );
	var_assign_null( "$argv",		PRONE_EXTERNAL, VAR_IS_GLOBAL );

	/* added for safety, as they depend on actual array index used: */
	var_assign_null( "$GLOBALS",		PRONE_EXTERNAL_MAYBE, VAR_IS_SUPERGLOBAL );
	var_assign_null( "$_SERVER",		PRONE_EXTERNAL_MAYBE, VAR_IS_SUPERGLOBAL );
	var_assign_null( "$HTTP_SERVER_VARS",	PRONE_EXTERNAL_MAYBE, VAR_IS_GLOBAL );
}


// ==========================================================================
// #### PHP functions, classes and namespaces ###############################
// ==========================================================================


/* Change variable context to local variables.
   Note that lambda functions do not have fn_name, which means
   this argument may be passed as an empty string!
*/
void function_start( const char *fn_name )
{
	struct s_var *sg_first, *sg_last, *pvar;

	assert( fn_name != NULL );

#if YYDEBUG
	if( opt.debug3 )
		fprintf( stderr, "function %s%s%s() {\n", current_class, (current_class[0] != '\0' ? "::" : ""), fn_name );
#endif
	context_index++;
	assert( context_index >= CONTEXT_LOCAL0 );
	if( context_index >= MAX_NEST )
		{
		if( opt.warn )
			fprintf( stderr, "Warning: maximum function definition nesting reached (include loop?). Ignoring.\n" );
		// leave context_vars the same
		return;  /* TODO: Handle this better */
		}
	context_fn[context_index] = function_add( fn_name, current_class );
	assert( context_fn[context_index] != NULL );
	assert( context_fn[context_index]->hard_links >= 0 );

	context_vars = &( context_fn[context_index]->vars_local );

	if( context_fn[context_index]->vars_local != NULL  ||
	    context_fn[context_index]->hard_links <= 0 )
		context_fn[context_index]->hard_links++;
		// this is the redefinition of a function

	sg_first = sg_last = context_fn[context_index]->vars_local;
		// start with any previous local variable, if
		// this is the redefinition of a function
		// (the first variable on a local list is always a superglobal)
	assert( sg_first == NULL  ||  sg_first->is_global != VAR_IS_LOCAL );

	// link all superglobals here
	for( pvar = vars_global;  pvar != NULL;  pvar = pvar->next[CONTEXT_GLOBAL] )
		{
		if( (pvar->is_global & VAR_IS_SUPERGLOBAL) != 0 )
			{
			if( sg_last == NULL )
				sg_first = sg_last = pvar;
			else if( sg_first != pvar )
				sg_last = sg_last->next[context_index] = pvar;
			}
		}
	assert( sg_last == NULL  ||  sg_last->next[context_index] == NULL );
	context_fn[context_index]->vars_local = sg_first;
	assert( context_fn[context_index]->vars_local != NULL );
		// there is always at least one superglobal
}


/* Creates a new function record (if it does not exist)
   and returns link to the exiting or newly created
   record.
   Note that function and class name searches are performed case-insensitively.
   Functions with unknown name (fn_name is "" or "?") are created with name "?".
   Never returns NULL.
   If class_name=="", this means "no class".

   TODO: Because class inheritance is not fully supported, if "fn_name" and
   "class_name" are something like:
	CLASS1::fn_name1::fn_name2::fn_name3  and  CLASS4  or
	CLASS1::CLASS2::CLASS3::fn_name3      and  CLASS4  or
	CLASS1::fn_name3                      and  CLASS4
   function_add() will behave as if it was called with:
	fn_name3  and  CLASS4
*/
struct s_function *function_add( const char *fn_name, const char *class_name )
{
	struct s_function **pp, *pfn;
	const char *p;
	int i;

	assert( fn_name    != NULL );
	assert( class_name != NULL );

	if( fn_name[0] == '\0' )
		fn_name = "?";
		// function name is unknown

	if( strcasecmp(class_name, "$this") == 0  ||  strcasecmp(class_name, "this")   == 0  ||
	    strcasecmp(class_name, "self")  == 0  ||  strcasecmp(class_name, "static") == 0 )
		class_name = current_class;
	else if( class_name[0] == '$'   ||  strcasecmp(class_name, "parent") == 0  ||
	                                    strcmp    (class_name, "?"     ) == 0 )
		class_name = "*";

	/* do not do this, to ensure separate namespace between classes and functions
	if( strcmp(fn_name, class_name) == 0 )
		class_name = "";  // this is a constructor
	*/

	/* TODO: Support class inheritance */
	p = strrchr( fn_name, ':' );
	if( p != NULL )
		fn_name = p + 1;

	for( pp = &functions;  (*pp) != NULL;  pp = &((*pp)->next) )
		{
		if( strcasecmp((*pp)->name,    fn_name   ) == 0  &&
		    strcasecmp((*pp)->ofclass, class_name) == 0 )
			return *pp;  // found existing record
		}

	// not found: create new record
	pfn = malloc( sizeof(struct s_function) );
	if( pfn == NULL )
		{
		if( opt.warn )
			fprintf( stderr, "Out of memory adding new function \"%s%s%s()\".\n",
			         class_name, (class_name[0]=='\0' ? "" : "::"), fn_name );
		exit( EXIT_ERROR );
		}
	strncpy( pfn->name, fn_name, LEN_VSTRING );
	pfn->name[LEN_VSTRING] = '\0';
	strncpy( pfn->ofclass, class_name, LEN_VSTRING );
	pfn->ofclass[LEN_VSTRING] = '\0';
	pfn->is_defined = 0;
	pfn->hard_links = 1;
	pfn->was_used_before_defined = 0;
	strcpy( pfn->yylloc_filename, yylloc.filename );
	pfn->yylloc = yylloc;
	pfn->yylloc.filename = pfn->yylloc_filename;
	for( i = 0;  i < PARSE_VIRUS_NUM;  i++ )
		pfn->prone[i] = PRONE_NONE;
		// this is (currently) lost: ... = ( strlen(fn_name)>LEN_VSTRING || strlen(class_name)>LEN_VSTRING ? PRONE_OBFUSCATED_MAYBE : PRONE_NONE );
	pfn->prone_return = PRONE_NONE;
	pfn->vars_local = NULL;
	pfn->calls_first = pfn->calls_last = NULL;
	pfn->next = NULL;
	*pp = pfn;
	return pfn;
}


/* Delete all local variables, preserving links to superglobals.
   Change variable context to global variables.
   If "was_defined" is true (!=0), set context_fn->is_defined to
   true as well.
*/
void function_end( int was_defined )
{
	struct s_var *p, *p2;

#if YYDEBUG
	if( opt.debug4 )
		fprintf( stderr, "Deleting local variables, leaving only superglobals:\n" );
#endif
	if( context_index >= MAX_NEST )
		{
		context_index--;
		assert( context_index >= CONTEXT_LOCAL0  ||  context_index == CONTEXT_GLOBAL );
		// leave context_vars the same
		return;  // ignoring function!
		}
	arg_list_reset();
		// to avoid lingering links,
		// "just in case" global vars were linked
	if( context_fn[context_index] != NULL )  // "just in case"
		{
		assert( context_vars == &(context_fn[context_index]->vars_local) );
		assert( context_fn[context_index]->hard_links >= 1 );
		context_fn[context_index]->hard_links--;

		// delete all links of the current context, to local variables
		p = context_fn[context_index]->vars_local;
		while( p != NULL )
			{
			p2 = p->next[context_index];
			if( p->is_global == VAR_IS_LOCAL )
				{
#if YYDEBUG
				if( opt.debug4 )
					fprintf( stderr, "\tlocal %s deleted\n", p->name );
#endif
				free( p );
				}
			else
				{
				// don't free(), but remove from this list
				p->next[context_index] = NULL;
				// "just in case", but need to remove assertion at
				// end of var_global_to_local() if you remove this
				}
			p = p2;
			}
		if( context_fn[context_index]->hard_links <= 0 )
			context_fn[context_index]->vars_local = NULL;
			// completely delete the functions local variables list
			// only after all references to this definition are gone

		context_fn[context_index]->is_defined = ( context_fn[context_index]->is_defined || was_defined );
		}

	context_index--;
	assert( context_index >= CONTEXT_LOCAL0  ||  context_index == CONTEXT_GLOBAL );

	if( context_index == CONTEXT_GLOBAL )
		context_vars = &vars_global;
	else
		{
		assert( context_fn[context_index] != NULL );
		context_vars = &( context_fn[context_index]->vars_local );
		}

#if YYDEBUG
	if( opt.debug3 )
		fprintf( stderr, "} function\n" );
#endif
}


/* Registers a function call.
   Does nothing if fn_name is "" or "?".
   "class_name" should have a class name or "$this", "self" or "static".
   Otherwise, it will be turned into "*" for "unknown" or "any" object.
   Note that this malloc()s a copy of *pfnc, instead of linking *pfnc itself.
   Returns a prone value that describes the function's return value.
   pfnc can be NULL if there are no arguments.
   Note that function and class name searches are performed case-insensitively.
   If class_name=="", this means "no class".

   TODO: Because class inheritance is not fully supported, if "fn_name" and
   "class_name" are something like:
	CLASS1::fn_name1::fn_name2::fn_name3  and  CLASS4  or
	CLASS1::CLASS2::CLASS3::fn_name3      and  CLASS4  or
	CLASS1::fn_name3                      and  CLASS4
   fn_call() will behave as if it was called with:
	fn_name3  and  CLASS4
*/
t_prone fn_call( const char *fn_name, const char *class_name, struct s_function_call *pfnc )
{
	struct s_function_call fnc, *new_pfnc;
	struct s_function *pfn, *cur_pfn;
	t_prone prone, prone_arg;
	const char *p;
	int i;

	assert( fn_name    != NULL );
	assert( class_name != NULL );

	if( fn_name[0] == '\0'  ||  strcmp(fn_name, "?") == 0 )
		return ( pfnc == NULL ? PRONE_NONE : pfnc->prone_args )
		       | PRONE_OBFUSCATED_MAYBE | PRONE_EXTERNAL_MAYBE;
		// function name is unknown

	if( strcasecmp(class_name, "$this") == 0  ||  strcasecmp(class_name, "this")   == 0  ||
	    strcasecmp(class_name, "self")  == 0  ||  strcasecmp(class_name, "static") == 0 )
		class_name = current_class;
	else if( class_name[0] == '$'   ||  strcasecmp(class_name, "parent") == 0  ||
	                                    strcmp    (class_name, "?"     ) == 0 )
		class_name = "*";

	/* do not do this, to ensure separate namespace between classes and functions
	if( strcmp(fn_name, class_name) == 0 )
		class_name = "";  // this is a constructor
	*/

	/* TODO: Support class inheritance */
	p = strrchr( fn_name, ':' );
	if( p != NULL )
		fn_name = p + 1;

	if( pfnc == NULL )
		{
		pfnc = &fnc;
		fn_call_arg( pfnc, 0, PRONE_NONE );
		}

	new_pfnc = malloc( sizeof(struct s_function_call) );
	if( new_pfnc == NULL )
		{
		if( opt.warn )
			fprintf( stderr, "Out of memory registering function call \"%s%s%s()\".\n",
			         class_name, (class_name[0]=='\0' ? "" : "::"), fn_name );
		exit( EXIT_ERROR );
		}
	*new_pfnc = *pfnc;
	new_pfnc->next = NULL;

	pfn = function_add( fn_name, class_name );
	assert( pfn != NULL );
	if( pfn->calls_last == NULL )
		pfn->calls_first = pfn->calls_last = new_pfnc;
	else
		pfn->calls_last = pfn->calls_last->next = new_pfnc;

	if( !pfn->is_defined )
		{
		// functions are generally defined before used, so this is strange,
		// but it might also be a PHP built-in;
		// just assume return value depends on all input arguments
		pfn->was_used_before_defined = 1;
		prone = new_pfnc->prone_args;
		}
	else
		{
		if( context_index >= CONTEXT_LOCAL0  &&  context_index < MAX_NEST )
			cur_pfn = context_fn[context_index];  // fine if NULL
		else
			cur_pfn = NULL;
			// do nothing if there is too much nesting, or in a nameless function

		prone = (pfn->prone_return    & ~PRONE_FN_ARGS_BITS) |
		        (new_pfnc->prone_args &  PRONE_FN_ARGS_BITS);
		// but now look at PRONE_FN_ARGS_BITS to combine further
		// conditions, based on calling arguments
		for( prone_arg = PRONE_FN_ARG_0;  prone_arg != 0ULL;  prone_arg <<= 1 )
			{
			for( i = 0;  i < PARSE_VIRUS_NUM;  i++ )
				{
				if( (pfn->prone_return & new_pfnc->prone[i] & prone_arg) != 0 )
					prone |= ( new_pfnc->prone_args & prone_masks[i] );
				}
			}
		if( cur_pfn != NULL )
			{
			// handle nested function calls
			for( i = 0;  i < PARSE_VIRUS_NUM;  i++ )
				{
				if( pfn->prone[i] != 0ULL )
					cur_pfn->prone[i] |= ( new_pfnc->prone_args & PRONE_FN_ARGS_BITS );
					/* TODO: Be more insightful on which PRONE_FN_ARGS_BITS
					   each argument actually had set, and support this on
					   functions not yet defined */
				}
			}
		}

#if YYDEBUG
	if( opt.debug3 )
		debug_trace( fn_name, class_name, prone, '(' );
#endif
	return prone;
}


/* Registers a function call argument.
   Will set (index==0) or merge (index>0) "prone" with each of pfnc->prone[].
   If index==0, will also set pfnc->next to NULL ("just in case").
   This is the "index"th argument in this function call.
*/
void fn_call_arg( struct s_function_call *pfnc, int index, t_prone prone )
{
	t_prone prone_arg;
	int i;

	assert( pfnc != NULL );
	assert( index >= 0 );

	if( index <= 0 )
		pfnc->prone_args  = prone;
	else
		pfnc->prone_args |= prone;
	// preserve PRONE_FN_ARGS_BITS

	prone_arg = PRONE_FN_ARG_0 << index;
	for( i = 0;  i < PARSE_VIRUS_NUM;  i++ )
		{
		if( (prone & prone_masks[i]) != 0 )
			{
			if( index <= 0 )
				pfnc->prone[i]  = prone_arg;
			else
				pfnc->prone[i] |= prone_arg;
			}
		else if( index <= 0 )
			pfnc->prone[i] = 0ULL;
		}
	if( index <= 0 )
		pfnc->next = NULL;
}


/* Checks all function calls registered in "functions" and returns one of
   PARSE_* (which will be PARSE_OK if nothing found).
   Argument is "current" PARSE_* error. Returned value will be "php" unless
   fn_call_check() is called with PARSE_OK.
   It also frees all that structure (hence the need to call this function even
   if fn_call_check() is called with PARSE_OK).
   Note that function and class name searches are performed case-insensitively.
*/
int fn_call_check( int php )
{
	struct s_function *pfn, *pfn2;
	struct s_function_call *pfnc, *pfnc2;
	int i;

#if YYDEBUG
	if( opt.debug3 )
		fprintf( stderr, "Checking function calls.\n" );
#endif
	for( pfn = functions;  pfn != NULL;  pfn = pfn2 )
		{
		pfn2 = pfn->next;

		if( pfn->was_used_before_defined  &&  php == PARSE_OK )
			{
			// functions are generally defined before used, so this is strange
			if( pfn->is_defined  &&  (pfn->prone_return & PRONE_EXTERNAL_BITS) != 0  &&
			    !opt.disable_obfuscation )
				{
				yylloc = pfn->yylloc;  // report error location correctly
				php = PARSE_OBFUSCATION;
				}
			// case !pfn->is_defined already handled by fn_call()
			}

		for( pfnc = pfn->calls_first;  pfnc != NULL;  pfnc = pfnc2 )
			{
			pfnc2 = pfnc->next;
			if( pfn->is_defined  &&  php == PARSE_OK )
				{
				for( i = 0;  i < PARSE_VIRUS_NUM;  i++ )
					{
					if( (pfnc->prone[i] & pfn->prone[i] & PRONE_FN_ARGS_BITS) != 0 )
						{
#if YYDEBUG
						if( opt.debug3 )
							fprintf( stderr, "Found error condition in call to %s%s%s()\n",
							         pfn->ofclass, (pfn->ofclass[0]=='\0' ? "" : "::"), pfn->name );
#endif
						yylloc = pfn->yylloc;  // report error location correctly
						php = PARSE_VIRUS_0 + i;
						break;
						}
					}
				}
			free( pfnc );
			}

		free( pfn );
		}
	functions = NULL;
	return php;
}


/* Entered a class block.
   class_name can be an empty string to reset current_class.
   If class_name=="", this means "no class".
*/
void class_start( const char *class_name )
{
	assert( class_name != NULL );

#if YYDEBUG
	if( opt.debug2  &&  class_name[0] != '\0' )
		fprintf( stderr, "class %s {\n", class_name );
#endif
	strncpy( current_class, class_name, LEN_VSTRING );
	current_class[ LEN_VSTRING ] = '\0';
}


void class_end( void )
{
#if YYDEBUG
	if( opt.debug2  &&  current_class[0] != '\0' )
		fprintf( stderr, "} class\n" );
#endif
	current_class[0] = '\0';
}


/* Called with "" at the start of processing a file,
   and at every "namespace" declaration.
*/
void namespace_start( const char *space_name )
{
	assert( space_name != NULL );
	strncpy( current_namespace, space_name, LEN_VSTRING );
	current_namespace[ LEN_VSTRING ] = '\0';
}


/* Called just before a new file is opened for inclusion,
   or just before a "namespace" declaration.
*/
void namespace_end( void )
{
	current_namespace[0] = '\0';
}


// ==========================================================================
// #### PHP variables #######################################################
// ==========================================================================


/* Adds a variable with no value (i.e., type == TYPE_NULL).
   See var_assign().
*/
void var_assign_null( const char *name, int prone, int var_is )
{
	struct s_value sv;

	s_value_set( &sv, prone, TYPE_NULL, 0, NULL );
	var_assign( name, &sv, var_is );
}


/* Adds an object property.
   All properties are automatically superglobals.
   "property" should start with '$' for class variables, or no '$' for constants.
   If "prefix_dollar" is true or '$' (!=0), prefix a '$' char to "property",
   if it's not already there.
   "class_name" should have a class name or "$this", "self" or "static".
   Otherwise, it will be turned into "*" for "unknown" or "any" object.
   If class_name=="", this means "any class" (i.e., it will become "*").
   See var_assign().

   TODO: Because class inheritance is not fully supported, if "property" and
   "class_name" are something like:
	CLASS1::property1::property2::property3  and  CLASS4  or
	CLASS1::CLASS2::CLASS3::property3        and  CLASS4  or
	CLASS1::property3                        and  CLASS4
   var_assign_obj() will behave as if it was called with:
	property3  and  CLASS4
*/
void var_assign_obj( const char *property, const char *class_name, int prefix_dollar, int prone )
{
	struct s_value sv, sv_name;
	const char *p;

	assert( class_name != NULL );
	assert( property   != NULL );

	if( strcasecmp(class_name, "$this") == 0  ||  strcasecmp(class_name, "this")   == 0  ||
	    strcasecmp(class_name, "self")  == 0  ||  strcasecmp(class_name, "static") == 0 )
		class_name = current_class;
	else if( class_name[0] == '$'   ||  strcasecmp(class_name, "parent") == 0  ||
	         class_name[0] == '\0'  ||  strcmp    (class_name, "?"     ) == 0 )
		class_name = "*";

	/* TODO: Support class inheritance */
	p = strrchr( property, ':' );
	if( p != NULL )
		property = p + 1;

	s_value_set( &sv_name, PRONE_NONE, TYPE_STRING, 0, class_name );
	s_value_cat( &sv_name, "::" );
	if( prefix_dollar  &&  property[0] != '$' )
		s_value_cat( &sv_name, "$" );
	s_value_cat( &sv_name, property );

	s_value_set( &sv,
	             ( prone | sv_name.prone ),
	             TYPE_OBJECT,
	             0,
	             class_name );

	var_assign( s_value_string(&sv_name), &sv, VAR_IS_SUPERGLOBAL );
		// object (properties) are always "superglobals"
}


/* Adds or modifies a variable named "name" with value "*pvalue" in the
   current vars array in context (context_vars). The new variable is a
   superglobal if (var_is & VAR_IS_SUPERGLOBAL) is non-zero, a global if
   (var_is & VAR_IS_GLOBAL) is non-zero, or a normal variable (local or
   global depending on the current context) otherwise.
   If "name" describes an object property (i.e., if it contains "::"
   other than at the beginning), then var_is is assumed to have
   VAR_IS_SUPERGLOBAL.
   "name" can be an object property if it starts with "CLASS::property"
   where "CLASS" is the class name, or "*" for unknown (any) class, in
   which case it will assign all classes/objects that contain a property
   with the same name. "name" should start with '$' for class variables,
   or no '$' for constants.
   When modifying a variable, both "prone"s are combined (ORed together).

   TODO: Because class inheritance is not fully supported, if "name" is
   something like:
	CLASS::property1::property2::property3
   var_assign() will behave as if it was called multiple times with:
	CLASS::property1
	*::property2
	*::property3
*/
void var_assign( const char *name, const struct s_value *pvalue, int var_is )
{
	char name2[ LEN_VSTRING+1 ];
	struct s_var *p, **pp, **pp_arg;
	const char *var_name;
	char *p_scope;
	int ix, is_global;
	t_prone prone;

	assert( context_vars != NULL );
	assert( name == NULL  ||  strlen(name) <= LEN_VSTRING );

	if( name == NULL  ||  name[0] == '\0' )
		{
#if YYDEBUG
		if( opt.debug4 )
			fprintf( stderr, "var_assign(NULL or \"\")!\n" );
#endif
		return;  // simply skip empty variable names
		}

	/* TODO: Support class inheritance */
	p_scope = strstr( name, "::" );
	if( p_scope != NULL )
		{
		if( p_scope != name )
			var_is |= VAR_IS_SUPERGLOBAL;
			// object (properties) are always "superglobals"
		p_scope = strstr( p_scope+2, "::" );
		if( p_scope != NULL )
			{
			var_is |= VAR_IS_SUPERGLOBAL;
				// object (properties) are always "superglobals"
			assert( strlen(name) < array_size(name2) );
			strcpy( name2, name );
			p_scope = name2 + (p_scope - name);
			name = (const char*) name2;
			p_scope[0] = '\0';
			}
		}

	prone = pvalue->prone;
	for(;;)	{
		if( context_vars == &vars_global  ||  (var_is & VAR_IS_SUPERGLOBAL) != 0 )
			prone &= ~PRONE_FN_ARGS_BITS;

		if( (var_is & (VAR_IS_GLOBAL | VAR_IS_SUPERGLOBAL)) != 0 )
			{
			pp = &vars_global;
			ix = CONTEXT_GLOBAL;
			is_global = VAR_IS_GLOBAL | (var_is & VAR_IS_SUPERGLOBAL);
			}
		else
			{
			pp = context_vars;
			ix = ( context_index >= MAX_NEST ? MAX_NEST-1 : context_index );
				// if context_index >= MAX_NEST, context_vars hold last useable context
			is_global = ( context_vars == &vars_global ? VAR_IS_GLOBAL : VAR_IS_LOCAL );
			}
#if YYDEBUG
		if( opt.debug4 )
			debug_trace( name, "", prone, ((var_is & VAR_IS_SUPERGLOBAL) != 0 ? 'S' : (pp == &vars_global ? 'G' : 'L')) );
#endif

		do	{
			for( ;  *pp != NULL;  pp = &((*pp)->next[ix]) )
				{
				if( name[0] == '*' )
					{
					var_name = strchr( (*pp)->name, ':' );
					if( var_name != NULL  &&  strcmp(var_name+2, name+3) == 0 )
						break;
					assert( var_name == NULL                  ||
						strncmp(var_name, name+1, 2) == 0 );
					}
				else
					{
					/* TODO: Somehow compare the class part case-insensitivelly! */
					if( strcmp((*pp)->name, name) == 0 )
						break;
					}
				}

			if( *pp == NULL )
				{
				// new variable
				p = malloc( sizeof(struct s_var) );
				if( p == NULL )
					{
					if( opt.warn )
						fprintf( stderr, "Out of memory adding new variable \"%s\".\n", name );
					exit( EXIT_ERROR );
					}
				strcpy( p->name, name );
				p->is_global = is_global;
				p->value = *pvalue;
				p->value.prone = prone;
				memset( p->next, 0, sizeof(p->next) );
				assert( NULL == 0 );  // can't seem to be able to do this with #if
				(*pp) = p;
		
				// link new var to local vars, if superglobal
				if( (var_is & VAR_IS_SUPERGLOBAL) != 0 )
					var_global_to_local( name, VAR_IS_SUPERGLOBAL );
				}
			else
				{
				// modifying existing variable
				p = *pp;
				prone |= p->value.prone;
				p->value = *pvalue;
				p->value.prone = prone;
				assert( (var_is & VAR_IS_SUPERGLOBAL) == 0  ||
				        p->name[0] != '$'                   ||
					strstr(p->name, "::") != NULL );
				}

			if( (var_is & VAR_IS_ARG) != 0 )
				{
				// link this variable to arg_list,
				// *if* it's not already linked
				for( pp_arg = &arg_list;  (*pp_arg) != NULL;  pp_arg = &((*pp_arg)->next[CONTEXT_ARGS]) )
					{
					if( (*pp_arg) == p )
						break;  // already linked
					}
				if( (*pp_arg) == NULL )
					{
					assert( p->next[CONTEXT_ARGS] == NULL );
						// can only do this here as this will not be true
						// if the entry is already linked
					*pp_arg = p;
					}
				}
	
			assert( pp != NULL  &&  *pp != NULL );
			pp = &((*pp)->next[ix]);
			}
			while( name[0] == '*'  &&  *pp != NULL );
	
		/* TODO: Support class inheritance */
		if( p_scope == NULL )
			break;
		//
		p_scope[0] = ':';
		if( strlen(p_scope) <= 2 )
			break;
		//
		p_scope[-1] = '*';
		name = (const char*) p_scope-1;
		p_scope = strstr( p_scope+2, "::" );
		if( p_scope != NULL )
			p_scope[0] = '\0';
		}
}


/* Makes global variable "name" also a local variable.
   If var_is == VAR_IS_SUPERGLOBAL, links this variable to all local
   variable lists.
*/
void var_global_to_local( const char *name, int var_is )
{
	struct s_var *pvar, **pp;
	int i;

	assert( name != NULL );

#if YYDEBUG
	if( opt.debug4 )
		fprintf( stderr, "%s %s;\n",
		         ( context_vars == &vars_global ?
		           "superglobal" :
		           ( (var_is & VAR_IS_SUPERGLOBAL) != 0 ?
		             "\tclass property (fake \"superglobal\")" :
		             "\tglobal" ) ),
		         name );
#endif
	if( context_vars == &vars_global )
		{
		assert( context_index == CONTEXT_GLOBAL );
		return;  // do nothing if there are no current local contexts
		}
	assert( context_index >= CONTEXT_LOCAL0 );

	for( pvar = vars_global;  pvar != NULL;  pvar = pvar->next[CONTEXT_GLOBAL] )
		{
		assert( pvar->is_global != VAR_IS_LOCAL );
		if( strcmp(pvar->name, name) == 0 )
			break;
		}

	/*
	was: <<If "name" is not global, attempt to create it locally.>>
	if( pvar == NULL )
		{
		// Create variable locally as function may be defined
		// before the variable is created. On the other hand
		// the variable may never be created, so use
		// PRONE_EXTERNAL_MAYBE; this is the default when
		// reading a missing variable, so we comment out this section
		if( context_index >= CONTEXT_LOCAL0 )
			{
			#if YYDEBUG
			if( opt.debug4 )
				fprintf( stderr, "Could not find global $%s: creating it locally\n", name );
			#endif
			var_assign_null( name, PRONE_EXTERNAL_MAYBE, VAR_IS_GLOBAL );
			}
		}
	else
	*/
	if( pvar != NULL )
		{
		for( i = (context_index >= MAX_NEST ? MAX_NEST-1 : context_index);
		     i >= CONTEXT_LOCAL0;  i-- )  // if context_index >= MAX_NEST, context_vars hold last useable context
			{
			if( context_fn[i] != NULL )  // "just in case"
				{
				for( pp = &(context_fn[i]->vars_local);  *pp != NULL;  pp = &((*pp)->next[i]) )
					{
					if( *pp == pvar )
						break;  // already linked...
					}
				if( *pp == NULL )
					{
					assert( pvar->next[i] == NULL );
					*pp = pvar;
					}
				}
			if( (var_is & VAR_IS_SUPERGLOBAL) == 0 )
				break;
			}
		}
}


/* Creates a variable record from its name string.
   "name" should start with '$' for class variables, or no '$' for constants.
   If "prefix_dollar" is true or '$' (!=0), prefix a '$' char to "name",
   if it's not already there.
   If "prefix_dollar" is exactly '^', this means to prefix the '$', but also
   that "name" refers to a global variable.
*/
void var_cast( struct s_var *pvar, const char *name, int prefix_dollar )
{
	struct s_value sv_name, *pvalue;

	assert( pvar != NULL );
	assert( name != NULL );

	if( prefix_dollar  &&  name[0] != '$' )
		{
		s_value_set( &sv_name, PRONE_NONE, TYPE_STRING, 0, "$" );
		s_value_cat( &sv_name, name );
		}
	else
		s_value_set( &sv_name, PRONE_NONE, TYPE_STRING, 0, name );

	strcpy( pvar->name, s_value_string(&sv_name) );
	pvar->is_global = ( prefix_dollar == '^' ? VAR_IS_GLOBAL : VAR_IS_LOCAL );

	pvalue = var_get_s_value( pvar->name, (prefix_dollar == '^' ? VAR_IS_GLOBAL : VAR_IS_CONTEXT) );
	if( pvalue == NULL )
		{
		if( pvar->name[0] == '$'                                                      &&
		    (context_vars == &vars_global || (pvar->is_global & VAR_IS_GLOBAL) != 0)  &&
		    strstr(pvar->name, "::") == NULL )
			sv_name.prone |= PRONE_EXTERNAL_MAYBE0;
			// see var_prone()
		s_value_set( &(pvar->value), sv_name.prone, TYPE_NULL, 0, NULL );
		}
	else
		{
		pvar->value = *pvalue;
		pvar->value.prone |= sv_name.prone;
		}
}


/* Creates an object property (variable) record from its strings.
   Variable value type becomes TYPE_OBJECT and its string becomes class_name.
   "property" should start with '$' for class variables, or no '$' for constants.
   If "prefix_dollar" is true or '$' (!=0), prefix a '$' char to "property",
   if it's not already there.
   "class_name" should have a class name or "$this", "self" or "static".
   Otherwise, it will be turned into "*" for "unknown" or "any" object.
   If class_name=="", this means "any class" (i.e., it will become "*").

   TODO: Because class inheritance is not fully supported, if "property" and
   "class_name" are something like:
	CLASS1::property1::property2::property3  and  CLASS4  or
	CLASS1::CLASS2::CLASS3::property3        and  CLASS4  or
	CLASS1::property3                        and  CLASS4
   var_cast_obj() will behave as if it was called with:
	property3  and  CLASS4
*/
void var_cast_obj( struct s_var *pvar, const char *property, const char *class_name, int prefix_dollar )
{
	struct s_value sv_name, *pvalue;
	const char *p;

	assert( pvar       != NULL );
	assert( class_name != NULL );
	assert( property   != NULL );

	if( strcasecmp(class_name, "$this") == 0  ||  strcasecmp(class_name, "this")   == 0  ||
	    strcasecmp(class_name, "self")  == 0  ||  strcasecmp(class_name, "static") == 0 )
		class_name = current_class;
	else if( class_name[0] == '$'   ||  strcasecmp(class_name, "parent") == 0  ||
	         class_name[0] == '\0'  ||  strcmp    (class_name, "?"     ) == 0 )
		class_name = "*";

	/* TODO: Support class inheritance */
	p = strrchr( property, ':' );
	if( p != NULL )
		property = p + 1;

	s_value_set( &sv_name, PRONE_NONE, TYPE_STRING, 0, class_name );
	s_value_cat( &sv_name, "::" );
	if( prefix_dollar  &&  property[0] != '$' )
		s_value_cat( &sv_name, "$" );
	s_value_cat( &sv_name, property );

	strcpy( pvar->name, s_value_string(&sv_name) );
	pvar->is_global = VAR_IS_GLOBAL | VAR_IS_SUPERGLOBAL;
		// object (properties) are always "superglobals"

	pvalue = var_get_s_value( pvar->name, VAR_IS_CONTEXT );
	s_value_set( &(pvar->value),
	             ( (pvalue == NULL ? PRONE_NONE : pvar->value.prone) | sv_name.prone ),
	                 // objects are never PRONE_EXTERNAL_MAYBE0 (see var_prone())
	             TYPE_OBJECT,
	             0,
	             class_name );
}


/* Returns pointer to the variable value, or NULL if not found.
   If "name" starts with "*::", then it means a particular property of
   any class. In this case the returned pointer will be to a static
   buffer containing a copy of the first found property's value, but
   a combination of all matching properties' "prone" values.
   "name" should start with '$' for variables, or no '$' for constants.
   If (var_is & VAR_IS_GLOBAL) is not zero, this variable name is
   searched in the global variables context, otherwise it is searched
   in the current context (local or global).

   TODO: Because class inheritance is not fully supported, if "name" is
   something like:
	CLASS::property1::property2::property3
   var_get_s_value() will behave as if it was called with:
	*::property3
   However, if "name" is something like:
	CLASS::property1
   the name is not changed.
*/
struct s_value *var_get_s_value( const char *name, int var_is )
{
	char name2[ LEN_VSTRING+1 ];
	static struct s_value sv;
	struct s_var *p;
	int have_sv, ix;
	const char *var_name;
	char *p_scope, *p_scope2;

	assert( name         != NULL );
	assert( context_vars != NULL );

	/* TODO: Support class inheritance */
	p_scope = strstr( name, "::" );
	if( p_scope != NULL )
		{
		p_scope = strstr( name, "::" );
		if( p_scope != NULL )
			{
			assert( strlen(name) < array_size(name2) );
			strcpy( name2, name );
			p_scope = name2 + (p_scope - name);
			for(;;)	{
				p_scope2 = strstr( p_scope+2, "::" );
				if( p_scope2 == NULL )
					break;
				if( strlen(p_scope2) <= 2 )
					{
					p_scope2[0] = '\0';
					break;
					}
				p_scope = p_scope2;
				}
			p_scope[-1] = '*';
			name = (const char*) p_scope-1;
			}
		}

	if( (var_is & VAR_IS_GLOBAL) != 0 )
		{
		p = vars_global;
		ix = CONTEXT_GLOBAL;
		}
	else
		{
		p = *context_vars;
		ix = ( context_index >= MAX_NEST ? MAX_NEST-1 : context_index );
		// if context_index >= MAX_NEST, context_vars hold last useable context
		}

	have_sv = 0;
	for( ;  p != NULL;  p = p->next[ix] )
		{
		if( name[0] == '*' )
			{
			var_name = strchr( p->name, ':' );
			if( var_name != NULL  &&  strcmp(var_name+2, name+3) == 0 )
				{
				if( !have_sv )
					{
					sv = p->value;
					have_sv = 1;
					}
				else
					sv.prone |= p->value.prone;
				}
			assert( var_name == NULL                  ||
				strncmp(var_name, name+1, 2) == 0 );
			}
		else
			{
			/* TODO: Somehow compare the class part case-insensitivelly! */
			if( strcmp(p->name, name) == 0 )
				return &(p->value);
			}
		}

	if( have_sv )
		return &sv;
	return NULL;
}


/* Returns this variable's "prone" state,
   or PRONE_EXTERNAL_MAYBE0 if not found.
   "name" should start with '$' for variables, or no '$' for constants.
   If (var_is & VAR_IS_GLOBAL) is not zero, this variable name is
   searched in the global variables context, otherwise it is searched
   in the current context (local or global).
*/
int var_prone( const char *name, int var_is )
{
	struct s_value *ps;

	assert( name != NULL );

	ps = var_get_s_value( name, var_is );
	if( ps != NULL )
		return ps->prone;
	return ( name[0] == '$'                                                   &&
	         (context_vars == &vars_global || (var_is & VAR_IS_GLOBAL) != 0)  &&
	         strstr(name, "::") == NULL                                       ?
	         PRONE_EXTERNAL_MAYBE0 : PRONE_NONE );
		// references to missing global classless vars may be an
		// attempt to use autoglobals, but references to missing
		// constants are constant strings
}


/* Returns PRONE_ACTION_MAYBE if str seems to contain PHP
   actions (functions) that could be used for virus actions
   if the string were applied in an eval().
   Returns PRONE_OBFUSCATED_MAYBE if the string does not
   seem to contain normal text or normal PHP code.
   Returns PRONE_NONE otherwise.
   Can return the combination of PRONE_ACTION_MAYBE and PRONE_OBFUSCATED_MAYBE.
*/
t_prone str_prone( const char *str )
{
	t_prone prone;
	int num_alpha, num_digit, num_punct, num_intl, num_other, num_total;
	double perc_alpha, perc_digit, perc_punct, perc_intl, perc_other;
	double avg;
	double delta_alpha, delta_digit, delta_punct, delta_intl, delta_other;
#if YYDEBUG
	static double perc_alpha_min = 100.0;
	static double perc_alpha_max =   0.0;
	static double perc_digit_min = 100.0;
	static double perc_digit_max =   0.0;
	static double perc_punct_min = 100.0;
	static double perc_punct_max =   0.0;
	static double perc_intl_min  = 100.0;
	static double perc_intl_max  =   0.0;
	static double perc_other_min = 100.0;
	static double perc_other_max =   0.0;
#endif
	int i;
	unsigned char c;

	prone = PRONE_NONE;

	if( strcasestr(str, "eval"          ) != NULL  ||
	    strcasestr(str, "mail"          ) != NULL  ||
	//  strcasestr(str, "imap_mail"     ) != NULL  ||  // included in "mail"
	    strcasestr(str, "socket_connect") != NULL  ||
	    strcasestr(str, "fsockopen"     ) != NULL )
		prone |= PRONE_ACTION_MAYBE;
		// these may be just part of a bigger function name

	num_alpha = num_digit = num_punct = num_intl = num_other = 0;
	num_total = strlen( str );
	if( num_total >= 15 )
		{
		// if there is a significant number of characters (to ensure
		// there is more than a signle [key]word), attempt a statistical
		// analysis on the character distribution
		for( i = 0;  i < num_total;  i++ )
			{
			c = str[i];
			if( c >= 128 )
				num_intl++;
			else if( isalpha(c) )
				num_alpha++;
			else if( isdigit(c) )
				num_digit++;
			else if( ispunct(c)  ||  isspace(c) )
				num_punct++;
			else
				num_other++;
			}
		perc_alpha = num_alpha / (double) max(num_total, 1);
		perc_digit = num_digit / (double) max(num_total, 1);
		perc_punct = num_punct / (double) max(num_total, 1);
		perc_intl  = num_intl  / (double) max(num_total, 1);
		perc_other = num_other / (double) max(num_total, 1);
		
		avg = (perc_alpha + perc_digit + perc_punct + perc_intl + perc_other) /
		      5.0;

		delta_alpha = perc_alpha - avg;
		delta_digit = perc_digit - avg;
		delta_punct = perc_punct - avg;
		delta_intl  = perc_intl  - avg;
		delta_other = perc_other - avg;
	
#if YYDEBUG
		if( opt.debug6 )
			{
			perc_alpha_min = min( perc_alpha_min, perc_alpha*100.0 );
			perc_alpha_max = max( perc_alpha_max, perc_alpha*100.0 );
			perc_digit_min = min( perc_digit_min, perc_digit*100.0 );
			perc_digit_max = max( perc_digit_max, perc_digit*100.0 );
			perc_punct_min = min( perc_punct_min, perc_punct*100.0 );
			perc_punct_max = max( perc_punct_max, perc_punct*100.0 );
			perc_intl_min  = min( perc_intl_min,  perc_intl *100.0 );
			perc_intl_max  = max( perc_intl_max,  perc_intl *100.0 );
			perc_other_min = min( perc_other_min, perc_other*100.0 );
			perc_other_max = max( perc_other_max, perc_other*100.0 );
	
			fprintf( stderr,
				"%s"
				"	Total characters: %i\n"
				"	Alphabetic characters:    %6i -> %6.1f%% d=%+5.1f%%  (seen [%5.1f%% -%5.1f%%] so far)\n"
				"	Numeric digit characters: %6i -> %6.1f%% d=%+5.1f%%  (seen [%5.1f%% -%5.1f%%] so far)\n"
				"	Punctuation and spaces:   %6i -> %6.1f%% d=%+5.1f%%  (seen [%5.1f%% -%5.1f%%] so far)\n"
				"	International characters: %6i -> %6.1f%% d=%+5.1f%%  (seen [%5.1f%% -%5.1f%%] so far)\n"
				"	Other characters:         %6i -> %6.1f%% d=%+5.1f%%  (seen [%5.1f%% -%5.1f%%] so far)\n",
				( opt.debug5 ? "  str_prone() for next string:\n" : "" ),
				num_total,
				num_alpha, perc_alpha*100.0, delta_alpha*100.0, perc_alpha_min, perc_alpha_max,
				num_digit, perc_digit*100.0, delta_digit*100.0, perc_digit_min, perc_digit_max,
				num_punct, perc_punct*100.0, delta_punct*100.0, perc_punct_min, perc_punct_max,
				num_intl,  perc_intl *100.0, delta_intl *100.0, perc_intl_min,  perc_intl_max,
				num_other, perc_other*100.0, delta_other*100.0, perc_other_min, perc_other_max
				);
				
			}
#endif

		/* TODO: Fine tune these statistics to detect virus sample vir3.php
		   this is currently producing more false positives than wanted...

		// limits from code samples
		if( perc_alpha < 0.35  ||  perc_alpha > 0.70  ||
		    perc_digit < 0.00  ||  perc_digit > 0.15  ||
		    perc_punct < 0.25  ||  perc_punct > 0.65  ||
		    perc_intl  < 0.00  ||  perc_intl  > 0.05  ||
		    perc_other < 0.00  ||  perc_other > 0.20 )
			prone |= PRONE_OBFUSCATED_MAYBE;
		*/


		// special cases
		if( (perc_alpha+perc_digit+perc_intl >  0.0  &&
			(perc_punct  < 0.01  ||    // probabily Base64 or similar
			 delta_punct > 0.50  ||    // probabily Base64-like encoding using punctuation characters
		         perc_other  > 0.20))  ||  // too many "other" ASCII characters
		    (perc_alpha+perc_digit+perc_intl <= 0.0  &&
			(perc_punct  > 0.50  ||    // probabily Base64-like encoding using punctuation characters
		         perc_other  > 0.50)) )    // too many "other" ASCII characters
			prone |= PRONE_OBFUSCATED_MAYBE;
		}

	return prone;
}


// ==========================================================================
// #### PHP grammar argument lists ##########################################
// ==========================================================================


/* Removes all ->next[CONTEXT_ARGS] links between variables linked in arg_list.
*/
void arg_list_reset( void )
{
	struct s_var *pvar, *pvar2;

	// clear all ->next[CONTEXT_ARGS] links: this makes sure
	// duplicate addition to this list is not possible
	pvar = arg_list;
	while( pvar != NULL )
		{
		pvar2 = pvar->next[CONTEXT_ARGS];
		pvar->next[CONTEXT_ARGS] = NULL;
		pvar = pvar2;
		}
	arg_list = NULL;
}


/* Goes through all ->next[CONTEXT_ARGS] variables linked in arg_list, and performs
   a bitwise OR between their ->value.prone and "prone".
*/
void arg_list_apply( t_prone prone )
{
	struct s_var *pvar;

	for( pvar = arg_list;  pvar != NULL;  pvar = pvar->next[CONTEXT_ARGS] )
		pvar->value.prone |= prone;
}


// ==========================================================================
// #### PHP constant values #################################################
// ==========================================================================


/* "Constructor" for struct s_value.
   Fills in all *pvalue fields with the appropriate supplied values.
   If type == TYPE_NULL or type == TYPE_OTHER, "string" must be NULL and "real" must be 0.
   If type == TYPE_REAL, "string" must be NULL.
   If type == TYPE_STRING or type == TYPE_OBJECT, "real" must be 0.
   If type == TYPE_OBJECT and "string" is "" or "?", sets it to "*" instead.
*/
void s_value_set( struct s_value *pvalue, int prone, int type, double real, const char *string )
{
	assert( pvalue != NULL );
	assert( type == TYPE_NULL  ||  type == TYPE_REAL  ||  type == TYPE_STRING  ||  type == TYPE_OBJECT  ||  type == TYPE_OTHER );

	pvalue->prone = prone;
	pvalue->type = type;
	switch( type )
		{
		case TYPE_NULL:  /* fall through */
		case TYPE_OTHER:
			assert( string == NULL );
			assert( real == 0.0 );
			pvalue->u.string[0] = '\0';
				// "just in case" as we occasionally
				// change type to TYPE_OBJECT
			break;
		case TYPE_REAL:
			assert( string == NULL );
			pvalue->u.real = real;
			break;
		case TYPE_STRING:  /* fall through */
		case TYPE_OBJECT:
			assert( real == 0.0 );
			if( string == NULL )
				pvalue->u.string[0] = '\0';
			else
				{
				strncpy( pvalue->u.string, string, LEN_VSTRING );
				pvalue->u.string[ LEN_VSTRING ] = '\0';
				}
			break;
		}
	if( type == TYPE_OBJECT  &&
	    (pvalue->u.string[0] == '\0'  ||  strcmp(pvalue->u.string, "?") == 0) )
		strcpy( pvalue->u.string, "*" );
}


/* Concatenates "string" to pvalue->u.string.
*/
void s_value_cat( struct s_value *pvalue, const char *string )
{
	int len;

	assert( pvalue != NULL  &&  string != NULL  &&
	        (pvalue->type == TYPE_STRING || pvalue->type == TYPE_OBJECT) );

	len = LEN_VSTRING - strlen(pvalue->u.string);
	if( len > 0 )
		{
		strncat( pvalue->u.string, string, len );
		if( len < strlen(string) )
			pvalue->prone |= PRONE_OBFUSCATED_MAYBE;
			// such a large string could be a
			// deliberate attempt at obfuscation
		}
}


/* Returns the numeric equivalent for "*pvalue"
*/
double s_value_real( struct s_value *pvalue )
{
	char *p;

	assert( pvalue != NULL );
	switch( pvalue->type )
		{
		case TYPE_NULL:    /* fall through */
		case TYPE_OBJECT:  /* fall through */
		case TYPE_OTHER:
			return 0.0;
		case TYPE_REAL:
			return pvalue->u.real;
		case TYPE_STRING:
			return strtod( pvalue->u.string, &p );
		}
	return 0.0;  // "just in case"
}


/* Returns the string equivalent for "*pvalue"
*/
const char *s_value_string( struct s_value *pvalue )
{
	static char str[1+2+DBL_DIG+2+1] = "";
		// sign + "0." + digits + "E1"

	assert( pvalue != NULL );
	str[0] = '\0';  // "just in case"
	switch( pvalue->type )
		{
		case TYPE_NULL:  /* fall through */
		case TYPE_OTHER:
			break;
		case TYPE_REAL:
			sprintf( str, "%g", pvalue->u.real );
			assert( strlen(str) < array_size(str) );
			return (const char *) str;
		case TYPE_STRING:  /* fall through */
		case TYPE_OBJECT:
			return (const char *) pvalue->u.string;
		}
	return (const char *) str;
}


/* Return a string with the (unescaped) character specified
   in "substring" (which can be missing the leading '\\').
   Examples:
	unescape_str("\\n")    = "\n"
	unescape_str("\\x32")  = "2"
	unescape_str("\\z")    = "z"
   If the unescaped character is the ASCII NUL ('\0'), it
   returns an empty string.
*/
const char *unescape_str( const char *substring )
{
	static char us[1+1] = "\0\0";
	char *p;
	long int n;

	assert( substring != NULL );

	if( *substring == '\\' )
		substring++;

	if( *substring == 'x'  ||  *substring == 'X' )
		{
		errno = 0;
		n = strtol( substring+1, &p, 16 );
		if( errno != 0 )
			n = 0L;  // returns the empty string
		if( n >= 256L )
			n = 255L;
		us[0] = (unsigned char) n;
		}
	else if( *substring >= '0'  &&  *substring <= '9' )
		{
		errno = 0;
		n = strtol( substring, &p, 8 );
		if( errno != 0 )
			n = 0L;  // returns the empty string
		if( n >= 256L )
			n = 255L;
		us[0] = (unsigned char) n;
		}
	else switch( *substring )
		{
	//	case 'a':  us[0] = '\a';  break;
	//	case 'b':  us[0] = '\b';  break;
		case 'f':  us[0] = '\f';  break;
		case 'n':  us[0] = '\n';  break;
		case 'r':  us[0] = '\r';  break;
		case 't':  us[0] = '\t';  break;
		case 'v':  us[0] = '\v';  break;
		default:   us[0] = *substring;
		           // just remove the "\"
		}

	return (const char *) us;
}


/* Present a debug line for function calls, variables and CONST_STRINGs
   These will be displayed as:
	class_name::name name_note = E:0 O:0 act:0 args:0x00000000000000 G
   If type is '"', display quotes around "name" and escape it.
   If type is '(', display "()" after "name".
   If type is anything else, display it as the last (right-most) character.
*/
#if YYDEBUG
#define DEBUG_TRACE_INDENT    "  "  // indentation string per trace line
#define DEBUG_TRACE_TEXT_LEN  37    // number of characters available after indent and before "="
#define DEBUG_TRACE_LINE_LEN  76    // number of characters in a trace line after indent
void debug_trace( const char *name, const char *class_name, t_prone prone, char type )
{
	char es[ DEBUG_TRACE_LINE_LEN+4+1 ];
		// with room for an escape and a couple more to detect
		// it doesn't fit on a line
	char *pes, *pcolon, *pparent, *pspace;
	int i, len, len_class, len_colon, len_name, len_parent, len_space;

	assert( name       != NULL );
	assert( class_name != NULL );

	if( type == '\0' )
		type = ' ';

	len = strlen( name );
	if( type == '"' )
		{
		type = ' ';
		es[0] = '"';
		pes = es+1;
		for( i = 0;  i < len  &&  pes < es+array_size(es)-2-1;  i++ )
			{
			switch( name[i] )
				{
			//	case '\a':  strcpy(pes, "\\a" );  pes+=2;  break;
			//	case '\b':  strcpy(pes, "\\b" );  pes+=2;  break;
				case '\f':  strcpy(pes, "\\f" );  pes+=2;  break;
				case '\n':  strcpy(pes, "\\n" );  pes+=2;  break;
				case '\r':  strcpy(pes, "\\r" );  pes+=2;  break;
				case '\t':  strcpy(pes, "\\t" );  pes+=2;  break;
				case '\v':  strcpy(pes, "\\v" );  pes+=2;  break;
				case  '"':  strcpy(pes, "\\\"");  pes+=2;  break;
				default:    *pes++ = name[i];              break;
				}
			}
		if( i >= len )
			strcpy( pes, "\"" );
		else
			*pes = '\0';
		assert( strlen(es) < array_size(es) );
		name = es;
		len = strlen( name );
		}

	len_class = strlen( class_name );
	len_name  = len;

	/* yes, it would be easier (but slower) to build the string to
	   output in a buffer and then cap it in length...
	*/
	if( type == '('  ||  type == ')' )
		{
		type = ' ';
		len += 2;
		pparent = "()";
		len_parent = 2;
		}
	else
		{
		pparent = "";
		len_parent = 0;
		}

	if( len_class > 0 )
		{
		len += len_class + 2;
		pcolon    = "::";
		len_colon = 2;
		}
	else
		{
		pcolon    = "";
		len_colon = 0;
		}

	if( len <= DEBUG_TRACE_TEXT_LEN )
		{
		pspace      = "";
		len_space   = DEBUG_TRACE_TEXT_LEN - len;
		}
	else if( len <= DEBUG_TRACE_LINE_LEN )
		{
		pspace      = "\n" DEBUG_TRACE_INDENT "^^";
		len_space   = 1+strlen(DEBUG_TRACE_INDENT)+DEBUG_TRACE_TEXT_LEN;
		}
	else if( len_class+len_colon >= DEBUG_TRACE_LINE_LEN-3 )
		{
		len_class   = DEBUG_TRACE_LINE_LEN-3;
		pcolon      = "";
		len_colon   = 0;
		name        = "";
		len_name    = 0;
		pparent     = "";
		len_parent  = 0;
		pspace      = "...\n" DEBUG_TRACE_INDENT "^^";
		len_space   = 3+1+strlen(DEBUG_TRACE_INDENT)+DEBUG_TRACE_TEXT_LEN;
		}
	else
		{
		len_name    = DEBUG_TRACE_LINE_LEN-len_class-len_colon-3-len_parent;
		pparent     = ( len_parent == 2 ? "...()" : "..." );
		len_parent += 3;
		pspace      = "\n" DEBUG_TRACE_INDENT "^^";
		len_space   = 1+strlen(DEBUG_TRACE_INDENT)+DEBUG_TRACE_TEXT_LEN;
		}

	fprintf( stderr,
		DEBUG_TRACE_INDENT "%.*s%s%.*s%s%-*s= E:%X O:%X act:%X arg:0x%014llX %c\n",
		len_class, class_name, pcolon,
		len_name,  name,       pparent,
		len_space, pspace,
		(int) ((prone) & PRONE_EXTERNAL_BITS  ) >> PRONE_EXTERNAL_SHR,
		(int) ((prone) & PRONE_OBFUSCATED_BITS) >> PRONE_OBFUSCATED_SHR,
		(int) ((prone) & PRONE_ACTION_BITS    ) >> PRONE_ACTION_SHR,
		      ((prone) & PRONE_FN_ARGS_BITS   ) >> PRONE_FN_ARGS_SHR,
		type );
}
#endif
