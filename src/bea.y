/*
Behaviour Analysis Scanner (bea)
bea.y
(C) 2012 Pedro Freire
	Free for research use.
	Contact phd@pedrofreire.com for other licensing.

Grammar parser file.
Designed for GNU bison.


NOTES:

This Bison grammar file is not meant to replicate any particular version of
the PHP language, and it is in many cases too permissive. This is by design,
to make the grammar simpler, and to allow for the grammar to accomodate any
future PHP evolution.

See bea.h for project notes.


TODO:

* Fix loop prone detection:
	$innocent = "angel";
	for( $i=0;  $i < 2;  $i++ )
		{
		if( $i == 1 )
			mail( $innocent, ... );
		$innocent = $_REQUEST["to"];
		}
  Either create semantic analysis trees, or perhaps handle loops
  similarly to how functions are being handled.

* Fix class property prone detection:
	class c
	{
		var $innocent;
		function f1()  {
			mail( $this->innocent, ... );
		}
		function f2()  {
			$this->innocent = $_REQUEST["to"];
		}
	}
	$angel = new c();
	$angel->f2();
	$angel->f1();
  bea currently assigns variable prone in file order.
  See issue above for possible solutions.

* Fix object method call:
	class c { ... }
	$angel = new c();
	$angel->f1();
  Currently it can't be determined which object is being called.
  But even semantic analysis would have a problem with various
  PHP obfuscation techniques.
  A partial fix would be to support
	variable '=' NEW constant '(' fn_call_args_opt ')'
  but a better fix is a general
	%type <value> expr
  and its necessary support.
*/


%{

#define _GNU_SOURCE  /* for strcasestr() and strcasecmp() */
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "bea.h"
#include "bea.tab.h"  /* for yylloc */


/* Bit masks that state which "...parse" bits are relevant for each
   virus detection type.
*/
t_prone prone_masks[ PARSE_VIRUS_NUM ] = {
	/* PARSE_EVAL   */  PRONE_EXTERNAL_BITS | PRONE_OBFUSCATED_BITS | PRONE_ACTION_BITS,
	/* PARSE_EXEC   */  PRONE_EXTERNAL_BITS | PRONE_OBFUSCATED_BITS | PRONE_ACTION_BITS,
	/* PARSE_MAIL   */  PRONE_EXTERNAL_BITS,
	/* PARSE_SOCKET */  PRONE_EXTERNAL_BITS,
	/* PARSE_FWRITE */  PRONE_EXTERNAL_BITS,
	};
#if (PARSE_EVAL   != PARSE_VIRUS_0  )  ||  (PARSE_EXEC   != PARSE_VIRUS_0+1)  || \
    (PARSE_MAIL   != PARSE_VIRUS_0+2)  ||  (PARSE_SOCKET != PARSE_VIRUS_0+3)  || \
    (PARSE_FWRITE != PARSE_VIRUS_0+4)  || \
    PARSE_VIRUS_NUM != 5
#error "Please reorder the above array!"
#endif


/* When parsing function arguments, this indicates which argument we're on.
*/
int fn_arg_index = 0;


/* Helper macro to make virus detection actions shorter.
*/
#define check_virus(disable, expr, parse_error, self, self_value)			\
{											\
	assert( (parse_error) >= PARSE_VIRUS_0               &&				\
	        (parse_error)-PARSE_VIRUS_0 < PARSE_VIRUS_NUM );			\
											\
	if( !(disable) )								\
		{									\
		if( ((expr) & prone_masks[(parse_error)-PARSE_VIRUS_0]) != 0 )		\
			return (parse_error);						\
		if( context_index >= CONTEXT_LOCAL0    &&  context_index < MAX_NEST  &&	\
		    context_fn[context_index] != NULL  &&  ((expr) & PRONE_FN_ARGS_BITS) != 0 )   \
			context_fn[context_index]->prone[(parse_error)-PARSE_VIRUS_0] |= ((expr) & PRONE_FN_ARGS_BITS);  \
		}									\
	self = (self_value);								\
}


/* Function called by yyparse() on parse error
*/
void yyerror( const char *str )
{
	if( opt.warn )
		{
		fprintf( stderr, "Error parsing file: %s\n", str );
		flex_display_file_nest( stderr, yylloc.line );
		}
	// yyparse() will now return with 1 (PARSE_ERROR)
}

%}


%locations
%error-verbose
%expect 15


%union {
	t_prone prone;  // one of PRONE_*
	struct s_value value;
	struct s_var var;
	struct s_function_call fn_call;
}


%token	<value>		CONST_NUMBER
%token	<value>		CONST_STRING
%token	<value>		CONST_BACKTICK
%token	<value>		CONST_LABEL
%token	<value>		PHP_VARIABLE
%token			PHP_GLOBALS

%nonassoc		';'
%nonassoc		OP_ARRAY	// =>
%nonassoc		'('  ')'

%left			','
%right			OP_ASSIGN	// += -= *= /= %= .= |= &= ^= <<= >>= ||= &&=
%right			'='
%left			'?'  ':'
%left			'&'
%left			OP_SIGN		// + -
%left			OP_BINARY	// * / % . | ^ << >> || && and or xor == === != !== <> < <= > >= instanceof
%nonassoc		OP_UNARY  '@'	// ! ~
%nonassoc		OP_INCDEC	// ++ --
%left			'['  ']'  '{'  '}'
%left			OP_OBJ  OP_CLASS  // -> ::
%right			'$'

/* see bea.l to see why this is commented-out
%token			PHP_TYPE  // any PHP data type, except "array"
*/
%token			ARRAY
%token			LIST

%token			EVAL
%token			MAIL
%token			SOCKET_CONNECT
%token			FSOCKOPEN
%token			FOPEN
%token			FWRITE
%token			FILE_PUT_CONTENTS

%token			PHP_OBFUSCATION
%token			PHP_OBFUSCATED_INCLUDE
%token			PHP_EXEC
%token			TRY
%token			CATCH
%token			THROW
%token			PHP_ECHO  // "echo", "print"; avoid collision with flex's ECHO

%token			IF
%token			ELSE
%token			ENDIF
%token			FOREACH
%token			AS
%token			ENDFOREACH
%token			FOR
%token			ENDFOR
%token			WHILE
%token			ENDWHILE
%token			DO
%token			SWITCH
%token			ENDSWITCH
%token			CASE
%token			DEFAULT
%token			BREAK
%token			CONTINUE
%token			RETURN
%token			GOTO
%token			DECLARE
%token			ENDDECLARE
%token			DEFINE
%token			PHP_INCLUDE       // "include",      "require"
%token			PHP_INCLUDE_ONCE  // "include_once", "require_once"

%token			FUNCTION
%token			GLOBAL

%token			NAMESPACE
%token			USE
%token			PHP_CLASS       // "class", "interface"
%token			EXTENDS
%token			IMPLEMENTS
%token			PHP_ABSTRACT    // "abstract", "final"
%token			PHP_VISIBILITY  // "public", "private", "protected"
%token			VAR
%token			CONST
%token			STATIC
%token			NEW
%token			CLONE

%token			PHP_UNKNOWN  // unexpected, unknown token

%type	<prone>		expr_no_cast
%type	<prone>		expr
%type	<prone>		expr_opt
%type	<prone>		expr_list
%type	<prone>		expr_list_opt
%type	<prone>		comma_expr_list_opt
%type	<prone>		array_def
%type	<prone>		array_list
%type	<prone>		label_list
%type	<var>		constant
%type	<var>		variable
%type	<var>		var_unit
%type	<var>		var_obj
%type	<var>		class_unit
%type	<var>		class_path
%type	<var>		obj_property
%type	<var>		obj_path
%type	<prone>		array_keys_opt
%type	<prone>		str_index_opt
%type	<fn_call>	fn_call_args_opt
%type	<fn_call>	fn_call_args
%type	<prone>		fn_call


%%


php:
	/* empty */
|	statements
;


/* ======================================================================= */
/* #### Statements ####################################################### */
/* ======================================================================= */

statements:
	           block_or_statement
|	statements block_or_statement
;

statements_opt:
	/* empty */
|	statements
;

statement:
	';'
|	expr_list ';'
/* 1 shift/reduce conflict from the 2 rules bellow: */
|	IF '(' expr_list ')' block_or_statement
|	IF '(' expr_list ')' block_or_statement ELSE block_or_statement
|	IF '(' expr_list ')' block_or_statement ELSE ':' statements_opt ENDIF
|	IF '(' expr_list ')' ':' statements_opt ENDIF
|	IF '(' expr_list ')' ':' statements_opt ELSE block_or_statement
|	IF '(' expr_list ')' ':' statements_opt ELSE ':' statements_opt ENDIF
|	FOREACH '(' foreach_as ')' block_or_statement
|	FOREACH '(' foreach_as ')' ':' statements_opt ENDFOREACH ';'
|	FOR '(' expr_list_opt ';' expr_list_opt ';' expr_list_opt ')' block_or_statement
|	FOR '(' expr_list_opt ';' expr_list_opt ';' expr_list_opt ')' ':' statements_opt ENDFOR ';'
|	WHILE '(' expr_list ')' block_or_statement
|	WHILE '(' expr_list ')' ':' statements_opt ENDWHILE ';'
|	DO block_or_statement WHILE '(' expr_list ')' ';'
|	SWITCH '(' expr_list ')' '{' switch_body '}'
|	SWITCH '(' expr_list ')' ':' switch_body ENDSWITCH ';'
|	BREAK    expr_opt ';'
|	CONTINUE expr_opt ';'
|	RETURN   expr_opt ';'				{ if(context_index>=CONTEXT_LOCAL0 && context_index<MAX_NEST && context_fn[context_index]!=NULL) context_fn[context_index]->prone_return |= $2; }
|	DECLARE '(' expr_list ')' block_or_statement
|	DECLARE '(' expr_list ')' ':' statements_opt ENDDECLARE ';'
|	GOTO CONST_LABEL ';'
|	CONST_LABEL ':'
/* 1 shift/reduce conflict from the 2 rules bellow: */
|	NAMESPACE CONST_LABEL				{  /* "block_or_semicolon" after NAMESPACE is implicit */
							namespace_end();
							namespace_start(s_value_string(&$2)); }
|	NAMESPACE					{ /* "block" after NAMESPACE is implicit */
							namespace_end(); }
|	USE CONST_LABEL                ';'		{ /* TODO: Better namespace support */ }
|	USE CONST_LABEL AS CONST_LABEL ';'		{ /* TODO: Better namespace support */ }
/* 1 shift/reduce conflict from the 1 rule bellow (and similar in "expr"): */
|	class_with_name '{' class_body '}'		{ class_end(); }
|	fn_with_name '(' fn_def_args_opt ')' block	{ function_end(1); }
|	GLOBAL global_var_list ';'
|	STATIC static_var_list ';'
|	TRY block_or_statement catch_list
|	THROW expr ';'
/* 2 shift/reduce conflicts from the 2 rules bellow: */
|	PHP_INCLUDE      '(' CONST_STRING ')' ';'	{ flex_open_file(s_value_string(&$3), 0); }
|	PHP_INCLUDE_ONCE '(' CONST_STRING ')' ';'	{ flex_open_file(s_value_string(&$3), 1); }
;


/* ======================================================================= */
/* #### Blocks ########################################################### */
/* ======================================================================= */

block:
	'{' statements_opt '}'
;

block_or_statement:
	block
|	statement
;

/* unused:
block_or_statement_opt:
	block
|	statement_opt
;
*/


/* ======================================================================= */
/* #### Control Structures ############################################### */
/* ======================================================================= */

foreach_as:
	expr_list AS     variable			{ var_assign_null($3.name, ($3.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $1, VAR_IS_CONTEXT | $3.is_global); }
|	expr_list AS '&' variable			{ var_assign_null($4.name, ($4.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $1, VAR_IS_CONTEXT | $4.is_global); }
|	expr_list AS     variable OP_ARRAY     variable	{ var_assign_null($3.name, ($3.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $1, VAR_IS_CONTEXT | $3.is_global);
							  var_assign_null($5.name, ($5.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $1, VAR_IS_CONTEXT | $5.is_global); }
|	expr_list AS '&' variable OP_ARRAY     variable	{ var_assign_null($4.name, ($4.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $1, VAR_IS_CONTEXT | $4.is_global);
							  var_assign_null($6.name, ($6.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $1, VAR_IS_CONTEXT | $6.is_global); }
|	expr_list AS     variable OP_ARRAY '&' variable	{ var_assign_null($3.name, ($3.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $1, VAR_IS_CONTEXT | $3.is_global);
							  var_assign_null($6.name, ($6.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $1, VAR_IS_CONTEXT | $6.is_global); }
|	expr_list AS '&' variable OP_ARRAY '&' variable	{ var_assign_null($4.name, ($4.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $1, VAR_IS_CONTEXT | $4.is_global);
							  var_assign_null($7.name, ($7.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $1, VAR_IS_CONTEXT | $7.is_global); }
;

switch_body:
	            switch_case
|	switch_body switch_case
;

switch_case:
	CASE expr ':' statements_opt
|	CASE expr ';' statements_opt
|	DEFAULT   ':' statements_opt
|	DEFAULT   ';' statements_opt
;

class_with_name:
	             PHP_CLASS CONST_LABEL class_extends  { class_start(s_value_string(&$2)); }
|	PHP_ABSTRACT PHP_CLASS CONST_LABEL class_extends  { class_start(s_value_string(&$3)); }
;

class_extends:
	/* empty */
|	EXTENDS label_list
|	                   IMPLEMENTS label_list
|	EXTENDS label_list IMPLEMENTS label_list
;

class_body:
	/* empty */
|	class_body class_item
;

class_item:
	visibility_opt       class_item_vars   ';'
|	visibility_opt VAR   class_item_vars   ';'
|	visibility_opt CONST class_item_consts ';'
|	visibility_opt fn_with_name '(' fn_def_args_opt ')' ';'    { function_end(0); }
|	visibility_opt fn_with_name '(' fn_def_args_opt ')' block  { function_end(1); }
	/* TODO: See also PHP's __set() */
;

class_item_vars:
	                    PHP_VARIABLE		{ var_assign_obj(s_value_string(&$1), current_class, '$', ($1.prone & ~PRONE_EXTERNAL_MAYBE0)     ); }
|	                    PHP_VARIABLE  '=' expr	{ var_assign_obj(s_value_string(&$1), current_class, '$', ($1.prone & ~PRONE_EXTERNAL_MAYBE0) | $3); }
|	class_item_vars ',' PHP_VARIABLE		{ var_assign_obj(s_value_string(&$3), current_class, '$', ($3.prone & ~PRONE_EXTERNAL_MAYBE0)     ); }
|	class_item_vars ',' PHP_VARIABLE  '=' expr	{ var_assign_obj(s_value_string(&$3), current_class, '$', ($3.prone & ~PRONE_EXTERNAL_MAYBE0) | $5); }
;

class_item_consts:
|	                      CONST_LABEL '=' expr	{ var_assign_obj(s_value_string(&$1), current_class,   0, ($1.prone & ~PRONE_EXTERNAL_MAYBE0) | $3); }
|	class_item_consts ',' CONST_LABEL '=' expr	{ var_assign_obj(s_value_string(&$3), current_class,   0, ($3.prone & ~PRONE_EXTERNAL_MAYBE0) | $5); }
;

visibility_opt:
	/* empty */
|	visibility_opt PHP_ABSTRACT
|	visibility_opt PHP_VISIBILITY
|	visibility_opt STATIC
;

catch_list:
/* 1 shift/reduce conflict from the 2 rules bellow: */
	/* empty */
|	catch_list CATCH '(' constant expr ')' block_or_statement
;


/* ======================================================================= */
/* #### Expressions ###################################################### */
/* ======================================================================= */

expr_no_cast:
	CONST_NUMBER					{ $$ = PRONE_NONE; }
|	CONST_STRING					{ $$ = $1.prone; }
|	constant					{ $$ = var_prone($1.name, $1.is_global); }
|	      variable					{ $$ = var_prone($1.name, $1.is_global); }
/* 1 shift/reduce conflict from the 2 rules bellow: */
|	DEFINE '(' CONST_STRING ',' expr comma_expr_list_opt ')'  { var_assign_null(s_value_string(&$3), $5, VAR_IS_SUPERGLOBAL); }
|	DEFINE '(' expr         ',' expr comma_expr_list_opt ')'  { /* TODO: Support dynamic named constants */ }
/* 4 shift/reduce conflicts from the 1 rule bellow: */
|	CLONE expr					{ $$ = $2;  /* need "expr" to handle "clone($obj->fn())" */ }
|	'&' expr					{ $$ = $2; }
|	expr_no_cast '?' expr_opt ':' expr_opt		{ $$ = $1 | $3 | $5; }
|	expr_no_cast OP_SIGN   expr			{ $$ = $1 | $3; }
|	expr_no_cast OP_BINARY expr			{ $$ = $1 | $3; }
|	expr_no_cast '&'       expr			{ $$ = $1 | $3; }
|	OP_SIGN  expr					{ $$ = $2; }
|	OP_UNARY expr					{ $$ = $2; }
|	CONST_LABEL '='    expr				{ $$ = $3;  /* used only in PHP's declare() */ }
|	variable    '='    expr				{ $$ = $3 | ($1.value.prone & ~PRONE_EXTERNAL_MAYBE0);
							var_assign_null($1.name, $$, VAR_IS_CONTEXT | $1.is_global); }
|	variable OP_ASSIGN expr				{ $$ = $3 | $1.value.prone | var_prone($1.name, $1.is_global);
							var_assign_null($1.name, $$, VAR_IS_CONTEXT | $1.is_global); }
|	LIST '(' list_var_list ')' '=' expr		{ $$ = $6; arg_list_apply($$); }
|	OP_INCDEC variable				{ $$ = $2.value.prone | var_prone($2.name, $2.is_global);
							var_assign_null($2.name, $$, VAR_IS_CONTEXT | $2.is_global); }
|	          variable OP_INCDEC			{ $$ = $1.value.prone | var_prone($1.name, $1.is_global);
							var_assign_null($1.name, $$, VAR_IS_CONTEXT | $1.is_global); }
|	'@' expr					{ $$ = $2; }
|	'(' expr_list ')'				{ $$ = $2; }
|	'(' constant  ')'				{ $$ = $2.value.prone; }
							/* this needs to be here so that "(CONSTANT)"
							   isn't interpreted as a cast */
|	ARRAY '(' array_def ')'				{ $$ = $3; }
|	fn_call						{ $$ = $1; }
|	FUNCTION '(' expr_list_opt ')' block		{ $$ = $3 | PRONE_OBFUSCATED_MAYBE | PRONE_EXTERNAL_MAYBE;  /* function_end(1); */
							  /* TODO: Better support anonymous function stack */ }
/* 1 shift/reduce conflict from the 1 rule bellow (and similar in "statement"): */
|	PHP_ECHO expr					{ $$ = $2; }
/* 1 shift/reduce conflict from the 2 rules bellow: (some removed due to reduce conflicts) */
|	'{' PHP_INCLUDE      expr			{ $$ = $3 | PRONE_OBFUSCATED_MAYBE | PRONE_EXTERNAL_MAYBE; }
|	'{' PHP_INCLUDE_ONCE expr			{ $$ = $3 | PRONE_OBFUSCATED_MAYBE | PRONE_EXTERNAL_MAYBE; }
/* TODO: Better support include() return values and include()s as blocks?
   Note that most of these are missing a trailing similar to: "block_or_statement_opt '}'"
|	'{' PHP_INCLUDE      '(' CONST_STRING ')'	{ $$ = $4.prone; flex_open_file(s_value_string(&$4), 0); }
|	'{' PHP_INCLUDE_ONCE '(' CONST_STRING ')'	{ $$ = $4.prone; flex_open_file(s_value_string(&$4), 1); }
|	'{' PHP_INCLUDE      '(' expr         ')'	{ $$ = $4 | PRONE_OBFUSCATED_MAYBE | PRONE_EXTERNAL_MAYBE; }
|	'{' PHP_INCLUDE_ONCE '(' expr         ')'	{ $$ = $4 | PRONE_OBFUSCATED_MAYBE | PRONE_EXTERNAL_MAYBE; }
|	'{' PHP_INCLUDE      CONST_STRING		{ $$ = $3.prone; flex_open_file(s_value_string(&$3), 0); }
|	'{' PHP_INCLUDE_ONCE CONST_STRING		{ $$ = $3.prone; flex_open_file(s_value_string(&$3), 1); }
*/

|	EVAL '(' expr ')'				{ check_virus(opt.disable_eval,   $3,       PARSE_EVAL,   $$, $3); }
|	PHP_EXEC '(' expr_list_opt ')'			{ check_virus(opt.disable_exec,   $3,       PARSE_EXEC,   $$, PRONE_EXTERNAL_MAYBE | $3); }
|	CONST_BACKTICK					{ check_virus(opt.disable_exec,   $1.prone, PARSE_EXEC,   $$, PRONE_EXTERNAL_MAYBE | $1.prone); }
|	MAIL '(' expr ',' expr_list ')'			{ check_virus(opt.disable_mail,   $3,       PARSE_MAIL,   $$, PRONE_NONE); }
|	SOCKET_CONNECT '(' expr ',' expr comma_expr_list_opt ')'  {
							  check_virus(opt.disable_socket, $5,       PARSE_SOCKET, $$, PRONE_NONE); }
|	FSOCKOPEN '(' expr ',' expr_list ')'		{ check_virus(opt.disable_socket, $3,       PARSE_SOCKET, $$, PRONE_NONE); }
|	FOPEN '(' expr ',' expr_list ')'		{ check_virus(opt.disable_fwrite, $3,       PARSE_FWRITE, $$, PRONE_NONE); }
|	FWRITE '(' expr ',' expr comma_expr_list_opt ')'  {
							  check_virus(opt.disable_fwrite, $5,       PARSE_FWRITE, $$, PRONE_NONE); }
|	FILE_PUT_CONTENTS '(' expr ',' expr comma_expr_list_opt ')'  {
							  check_virus(opt.disable_fwrite, $3|$5,    PARSE_FWRITE, $$, PRONE_NONE); }
;

expr:
	                 expr_no_cast			{ $$ = $1; }
|	'(' ARRAY    ')' expr				{ $$ = $4; }
|	'(' constant ')' expr				{ $$ = $4; }
;

expr_opt:
	/* empty */					{ $$ = PRONE_NONE; }
|	expr						{ $$ = $1; }
;


/* ======================================================================= */
/* #### Constants, Variables and Class Properties ######################## */
/* ======================================================================= */


/* Scoped or unscoped constant name.
   $$.name has constant name (without leading '$'),
   $$.value is TYPE_NULL (no scoping) or TYPE_OBJECT with value as returned
   by class_path.
*/
constant:
	           CONST_LABEL				{ var_cast    ( &$$, s_value_string(&$1),                            0 );  $$.value.prone |= $1.prone; }
|	class_path CONST_LABEL				{ var_cast_obj( &$$, s_value_string(&$2), s_value_string(&$1.value), 0 );  $$.value.prone |= $1.value.prone | $2.prone; }
;


/* Any variable name that can be assigned values.
   $$.name has variable name (with or without leading '$'),
   $$.value is preserved.
*/
variable:
	           var_unit     str_index_opt		{ $$ = $1;  $$.value.prone |= $2; }
|	class_path var_unit     str_index_opt		{ var_cast_obj( &$$, $2.name, s_value_string(&$1.value), '$' );  $$.value.prone |= $1.value.prone | $2.value.prone | $3; }
|	obj_path   obj_property str_index_opt		{ var_cast_obj( &$$, $2.name, s_value_string(&$1.value), '$' );  $$.value.prone |= $1.value.prone | $2.value.prone | $3; }
;


/* "$var" constructions (recursive for "$$var", "$$$var", etc.).
   $$.name has "?" or intended variable name with leading '$',
   $$.value is TYPE_NULL.
*/
var_unit:
	PHP_VARIABLE                     array_keys_opt	{ var_cast( &$$, s_value_string(&$1),       '$' );  $$.value.prone |= $1.prone | $2; }
|	PHP_GLOBALS '[' CONST_STRING ']' array_keys_opt	{ var_cast( &$$, s_value_string(&$3),       '^' );  $$.value.prone |= $3.prone | $5; }
|	PHP_GLOBALS '[' CONST_LABEL  ']' array_keys_opt	{ var_cast( &$$, s_value_string(&$3),       '^' );  $$.value.prone |= $3.prone | $5; }
|	PHP_GLOBALS '[' expr_opt     ']' array_keys_opt	{ var_cast( &$$, "$GLOBALS",                '$' );  $$.value.prone |= $3 | $5; }
|	PHP_GLOBALS					{ var_cast( &$$, "$GLOBALS",                '$' ); }
|	'$'     var_unit				{ var_cast( &$$, s_value_string(&$2.value), '$' );  $$.value.prone |= $2.value.prone; }
|	'$' '{' expr     '}'             array_keys_opt	{ var_cast( &$$, "?",                       '$' );  $$.value.prone |= $3 | $5;
							  /* TODO: Support s_value_string(&$3) */ }
;


/* Anything that can be before the first "->" (except method calls),
   i.e., an object name, i.e., "$var" or "CONST"
   $$.name has "?" or intended object name (with or without leading '$'),
   $$.value is TYPE_OBJECT with class_name (CONST_LABEL) or "*".
*/
var_obj:
	var_unit					{ var_cast_obj( &$$, $1.name,             $1.name,             '$' );  $$.value.prone |= $1.value.prone; }
|	CONST_LABEL array_keys_opt			{ var_cast_obj( &$$, s_value_string(&$1), s_value_string(&$1),  0  );  $$.value.prone |= $1.prone | $2; }
;


/* A class name that preceeds a scope resolution operator (::).
   This can be specified directly on a CONST_LABEL, or indirectly
   in a var_unit.
   $$.name has "?",
   $$.value is TYPE_OBJECT with class_name (CONST_LABEL) or "*".
*/
class_unit:
	var_unit					{ var_cast_obj( &$$, "?", $1.name,             0 );  $$.value.prone |= $1.value.prone; }
|	CONST_LABEL					{ var_cast_obj( &$$, "?", s_value_string(&$1), 0 );  $$.value.prone |= $1.prone; }
|	STATIC						{ var_cast_obj( &$$, "?", "static",            0 ); }
;


/* Scope (::) path to a variable or constant, ending in OP_CLASS.
   $$.name has "?",
   $$.value is TYPE_OBJECT with class name (the right-most class
   name, and only if it's a CONST_LABEL) or "*" otherwise.
*/
class_path:
	           class_unit OP_CLASS			{ var_cast_obj( &$$, "?", s_value_string(&$1.value), 0 );  $$.value.prone |= $1.value.prone; }
|	class_path class_unit OP_CLASS			{ var_cast_obj( &$$, "?", s_value_string(&$2.value), 0 );  $$.value.prone |= $1.value.prone | $2.value.prone; }
;


/* Anything expressing a property that can be after a "->" (except method calls),
   i.e., "$var", "CONST" or "{expr}"
   $$.name has "?" or intended property name,
   $$.value is TYPE_OBJECT with value as returned by var_obj.
*/
obj_property:
	var_obj						{ $$ = $1;  if($$.name[0] == '$')  strcpy( $$.name, "?" ); }
|	'{' expr '}' array_keys_opt			{ var_cast_obj( &$$, "?", "*", 0 );  $$.value.prone |= $2 | $4; }
;


/* Object (->) path to a variable or constant, ending in OP_OBJ.
   $$.name has "?",
   $$.value is TYPE_OBJECT with class name (if there is a
   single scope resolution/object access operator and class name
   is in a CONST_LABEL) or "*" otherwise.
*/
obj_path:
	           var_obj OP_OBJ			{ var_cast_obj( &$$, "?", s_value_string(&$1.value), 0 );
	           					  $$.value.prone |= $1.value.prone; }
|	           var_obj '(' fn_call_args_opt ')' array_keys_opt OP_OBJ  {
							  var_cast_obj( &$$, "?", "*", 0 );
							  $$.value.prone |= fn_call($1.name, s_value_string(&$1.value), &$3) | $5; }
|	class_path var_obj OP_OBJ			{ var_cast_obj( &$$, "?", s_value_string(&$2.value), 0 );
							  $$.value.prone |= $1.value.prone | $2.value.prone; }
|	class_path var_obj '(' fn_call_args_opt ')' array_keys_opt OP_OBJ  {
							  var_cast_obj( &$$, "?", "*", 0 );
							  $$.value.prone |= fn_call($2.name, s_value_string(&$2.value), &$4) | $6; }
|	obj_path obj_property OP_OBJ			{ var_cast_obj( &$$, "?", "*", 0 );
							  $$.value.prone |= $1.value.prone | $2.value.prone; }
|	obj_path obj_property '(' fn_call_args_opt ')' array_keys_opt OP_OBJ  {
							  var_cast_obj( &$$, "?", "*", 0 );
							  $$.value.prone |= fn_call($2.name, s_value_string(&$2.value), &$4) | $6; }
;


array_keys_opt:
	/* empty */					{ $$ = PRONE_NONE; }
|	array_keys_opt '[' expr_opt ']'			{ $$ = $1 | $3; }
;


str_index_opt:
	/* empty */					{ $$ = PRONE_NONE; }
|	'{' expr '}'					{ $$ = $2; }
;


/* ======================================================================= */
/* #### Functions and Methods ############################################ */
/* ======================================================================= */

fn_call:
	NEW STATIC					    { $$ = fn_call( current_class,             "static",                   NULL ); }
|	NEW STATIC                '(' fn_call_args_opt ')'  { $$ = fn_call( current_class,             "static",                   &$4  ); }
|	NEW            var_obj				    { $$ = fn_call( s_value_string(&$2.value), s_value_string(&$2.value),  NULL ); }
|	NEW            var_obj    '(' fn_call_args_opt ')'  { $$ = fn_call( s_value_string(&$2.value), s_value_string(&$2.value),  &$4  ); }
|	NEW class_path var_obj				    { $$ = fn_call( s_value_string(&$3.value), s_value_string(&$3.value),  NULL ); }
|	NEW class_path var_obj    '(' fn_call_args_opt ')'  { $$ = fn_call( s_value_string(&$3.value), s_value_string(&$3.value),  &$5  ); }
|	NEW obj_path obj_property			    { $$ = $2.value.prone | $3.value.prone |                 PRONE_OBFUSCATED; }
|	NEW obj_path obj_property '(' fn_call_args_opt ')'  { $$ = $2.value.prone | $3.value.prone | $5.prone_args | PRONE_OBFUSCATED; }

|	           var_obj     '(' fn_call_args_opt ')' array_keys_opt  { $$ = fn_call( $1.name, "",                        &$3 ) | $5; }
|	class_path var_obj     '(' fn_call_args_opt ')' array_keys_opt  { $$ = fn_call( $2.name, s_value_string(&$1.value), &$4 ) | $6; }
|	PHP_OBFUSCATION        '(' expr_list_opt    ')' array_keys_opt  { $$ = $3 | $5 | PRONE_OBFUSCATED;  /* calling a PHP built-in function */ }
|	PHP_OBFUSCATED_INCLUDE '(' expr_list_opt    ')' array_keys_opt  { $$ = $3 | $5 | PRONE_OBFUSCATED;
							                  obfuscated_include_yylloc = yylloc;
							                  obfuscated_include_found = 1; // true
							                  /* calling a PHP built-in function */ }
|	obj_path obj_property  '(' fn_call_args_opt ')' array_keys_opt  {
							  $$ = fn_call( $2.name, s_value_string(&$1.value), &$4 ) | $6; }
;

fn_call_args_opt:
	/* empty */					{ fn_call_arg(&$$, 0, PRONE_NONE); }
|	fn_call_args					{ $$ = $1; }
;

fn_call_args:
	                 expr				{ fn_call_arg(&$$, fn_arg_index=0, $1); }
|	fn_call_args ',' expr				{ fn_call_arg(&$$, fn_arg_index++, $3); }
;

fn_with_name:
	FUNCTION     CONST_LABEL			{ function_start(s_value_string(&$2)); fn_arg_index=0; }
|	FUNCTION '&' CONST_LABEL			{ function_start(s_value_string(&$3)); fn_arg_index=0; }
;

fn_def_args_opt:
	/* empty */
|	fn_def_args
;

/* This rule runs after function_start() has already been called,
   so these variables are created locally.
   We need to create these arguments as local variables to avoid false
   positivies when updates are made to variables that seem not to have
   been created previously. Furthermore, we need to mark them as
   function arguments in their ".prone".

   Abbreviating half these combinations by using an auxiliary
	fn_def_hint_opt:
		/+ empty +/
	|	...
	;
   doesn't work as bison complains:
	warning: rule never reduced because of conflicts:
	fn_def_hint_opt: /+ empty +/
*/
fn_def_args:
	                                variable	   { var_assign_null($1.name, ($1.value.prone & ~PRONE_EXTERNAL_MAYBE0) |      (PRONE_FN_ARG_0 << fn_arg_index++), VAR_IS_CONTEXT); }
|	                fn_def_hint_opt variable	   { var_assign_null($2.name, ($2.value.prone & ~PRONE_EXTERNAL_MAYBE0) |      (PRONE_FN_ARG_0 << fn_arg_index++), VAR_IS_CONTEXT); }
|	                                variable '=' expr  { var_assign_null($1.name, ($1.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $3 | (PRONE_FN_ARG_0 << fn_arg_index++), VAR_IS_CONTEXT); }
|	                fn_def_hint_opt variable '=' expr  { var_assign_null($2.name, ($2.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $4 | (PRONE_FN_ARG_0 << fn_arg_index++), VAR_IS_CONTEXT); }
|	fn_def_args ','                 variable	   { var_assign_null($3.name, ($3.value.prone & ~PRONE_EXTERNAL_MAYBE0) |      (PRONE_FN_ARG_0 << fn_arg_index++), VAR_IS_CONTEXT); }
|	fn_def_args ',' fn_def_hint_opt variable	   { var_assign_null($4.name, ($4.value.prone & ~PRONE_EXTERNAL_MAYBE0) |      (PRONE_FN_ARG_0 << fn_arg_index++), VAR_IS_CONTEXT); }
|	fn_def_args ','                 variable '=' expr  { var_assign_null($3.name, ($3.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $5 | (PRONE_FN_ARG_0 << fn_arg_index++), VAR_IS_CONTEXT); }
|	fn_def_args ',' fn_def_hint_opt variable '=' expr  { var_assign_null($4.name, ($4.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $6 | (PRONE_FN_ARG_0 << fn_arg_index++), VAR_IS_CONTEXT); }
;

fn_def_hint_opt:
                 '&'
|	constant
|	constant '&'
|	ARRAY
|	ARRAY    '&'
;


/* ======================================================================= */
/* #### Miscellaneous Lists ############################################## */
/* ======================================================================= */

global_var_list:
	                    variable			{ var_global_to_local($1.name, VAR_IS_GLOBAL); }
|	global_var_list ',' variable			{ var_global_to_local($3.name, VAR_IS_GLOBAL); }
;

static_var_list:
	                    variable			{ var_assign_null($1.name, ($1.value.prone & ~PRONE_EXTERNAL_MAYBE0),      VAR_IS_CONTEXT); }
|	                    variable '=' expr		{ var_assign_null($1.name, ($1.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $3, VAR_IS_CONTEXT); }
|	static_var_list ',' variable			{ var_assign_null($3.name, ($3.value.prone & ~PRONE_EXTERNAL_MAYBE0),      VAR_IS_CONTEXT); }
|	static_var_list ',' variable '=' expr		{ var_assign_null($3.name, ($3.value.prone & ~PRONE_EXTERNAL_MAYBE0) | $5, VAR_IS_CONTEXT); }
;

list_var_list:
	                  variable			{ arg_list_reset();
	                  				  var_assign_null($1.name, ($1.value.prone & ~PRONE_EXTERNAL_MAYBE0), VAR_IS_ARG | $1.is_global); }
|	              ',' variable			{ arg_list_reset();
	                  				  var_assign_null($2.name, ($2.value.prone & ~PRONE_EXTERNAL_MAYBE0), VAR_IS_ARG | $2.is_global); }
|	list_var_list ',' variable			{ var_assign_null($3.name, ($3.value.prone & ~PRONE_EXTERNAL_MAYBE0), VAR_IS_ARG | $3.is_global); }
|	list_var_list ','				{ }
;

label_list:
	               CONST_LABEL			{ $$ = $1.prone; }
|	label_list ',' CONST_LABEL			{ $$ = $3.prone | $1; }
;


/* ======================================================================= */
/* #### Miscellaneous #################################################### */
/* ======================================================================= */

expr_list:
	              expr				{ $$ = $1; }
|	expr_list ',' expr				{ $$ = $1 | $3; }
;

expr_list_opt:
	/* empty */					{ $$ = PRONE_NONE; }
|	expr_list					{ $$ = $1; }
;

comma_expr_list_opt:
	/* empty */					{ $$ = PRONE_NONE; }
|	',' expr_list					{ $$ = $2; }
;

array_def:
	/* empty */					{ $$ = PRONE_NONE; }
|	array_list					{ $$ = $1; }
|	array_list ','					{ $$ = $1; }
;

array_list:
	                             expr		{ $$ = $1; }
|	               expr OP_ARRAY expr		{ $$ = $3; }
|	array_list ','               expr		{ $$ = $1 | $3; }
|	array_list ',' expr OP_ARRAY expr		{ $$ = $1 | $5; }
;
