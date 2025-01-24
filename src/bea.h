/*
Behaviour Analysis Scanner (bea)
bea.h
(C) 2012 Pedro Freire
	Free for research use.
	Contact phd@pedrofreire.com for other licensing.

Include file with common macros and function prototypes.


NOTES:

This application is currently in beta. Most bugs have been found and fixed,
but many small details still remain for later improvement. All these are
marked with a comment containing the upper-case word "TODO:".

Use this include file to locate functions and shared variables, but look at
each file to find comments at the top of each function explaining how to use
it.
*/

#define _GNU_SOURCE  /* for strcasestr() and strcasecmp() */
#include <limits.h>


/* Length for [...].value.string (VSTRING): STRING values,
   LABEL names including namespaces.
*/
#define LEN_VSTRING		2048


/* Length for files and their paths.
   Also add room for trailing '/'.
*/
#if LEN_VSTRING < PATH_MAX
#define LEN_PATH		(PATH_MAX+1)
#else
#define LEN_PATH		(LEN_VSTRING+1)
#endif


/* Maximum number of include() or function(){} nesting, or opened files.
   as well as context_index array indexes
*/
#define MAX_NEST		10
#define MAX_OPENED_FILES	20
#define CONTEXT_ARGS		 0
#define CONTEXT_GLOBAL		 1
#define CONTEXT_LOCAL0		 2


/* Maximum number of different PHP file extensions to search for,
   and maximum length for each. Also maximum number of include
   directories.
*/
#define MAX_EXTENSIONS		20
#define LEN_EXTENSION		15  // ".phtml"=6
#define MAX_INCLUDE_PATHS	30


/* Run-time semantic value types
*/
#define TYPE_NULL		0
#define TYPE_REAL		1
#define TYPE_STRING		2
#define TYPE_OBJECT		3  // .value.string holds the class name
#define TYPE_OTHER		4  // array, resource, ...


/* Degree of how each expression is prone to virus (PRONE).
   Based on wether it is built by external input (PRONE_EXTERNAL*)
   obfuscated (PRONE_OBFUSCATED) or containing action strings
   for eval (PRONE_ACTION).
   Final value is a bitwise OR of these values.
*/
#define PRONE_NONE		              0x00ULL
#define PRONE_EXTERNAL_MAYBE0	              0x01ULL  // reading innexistent variable
#define PRONE_EXTERNAL_MAYBE	              0x02ULL
#define PRONE_EXTERNAL		              0x04ULL
#define PRONE_EXTERNAL_BITS	              0x07ULL  // AND mask
#define PRONE_EXTERNAL_SHR	                 0     // >>
#define PRONE_OBFUSCATED_MAYBE	              0x08ULL
#define PRONE_OBFUSCATED	              0x10ULL
#define PRONE_OBFUSCATED_BITS	              0x18ULL  // AND mask
#define PRONE_OBFUSCATED_SHR	                 3     // >>
#define PRONE_ACTION_MAYBE	              0x20ULL
#define PRONE_ACTION		              0x40ULL
#define PRONE_ACTION_BITS	              0x60ULL  // AND mask
#define PRONE_ACTION_SHR	                 5     // >>
#define PRONE_FN_ARG_0		0x0000000000000100ULL  // shifted left by arg position
#define PRONE_FN_ARGS_BITS	0xFFFFFFFFFFFFFF00ULL  // AND mask
#define PRONE_FN_ARGS_SHR	                 8     // >>
//
#define MAX_PRONE_FN_ARGS	                56     // number of bits in PRONE_FN_ARGS_BITS
//
typedef unsigned long long int t_prone;  // data type for "prone" variables


/* Whether this variable is a [super]global.
   Final value is a bitwise OR of these values.
*/
#define VAR_IS_CONTEXT		0x0  // default for functions taking a "var_is" argument
#define VAR_IS_LOCAL		0x0
#define VAR_IS_GLOBAL		0x1
#define VAR_IS_SUPERGLOBAL	0x2
//
// This is not combined with the above macros, and is only used by var_assing():
#define VAR_IS_ARG		0x4  // ask var_assign() to also link this
				     // in arg_list_first/arg_list_last


/* yyparse() return values, indicating scan result.
*/
#define PARSE_OK		 0  // (bison) nothing found
#define PARSE_ERROR		 1  // (bison) error parsing the file
#define PARSE_ERROR_MEM		 2  // (bison) out of memory
#define PARSE_EVAL		10  // found suspicious eval()
#define PARSE_EXEC		11  // found external program execution with external provided data
#define PARSE_MAIL		12  // found mail() to external provided address
#define PARSE_SOCKET		13  // found socket connections to external provided address
#define PARSE_FWRITE		14  // found suspicious open/write to file with external provided data
#define PARSE_OBFUSCATION	20  // found suspicious string obfuscation
//
#define PARSE_VIRUS_0		10  // first return value for virus detection
#define PARSE_VIRUS_NUM		 5  // number of return values for virus detection


/* Exit codes, based on GREP.
*/
#define EXIT_FOUND		 0
#define EXIT_NOT_FOUND		 1
#define EXIT_ERROR		 2


/* Program options.
*/
extern struct s_opt {
	char extensions[ MAX_EXTENSIONS ][ LEN_EXTENSION+1 ];
	char include_path[ LEN_VSTRING+1 ];
	int help;
	int warn;
#if YYDEBUG
	int debug0;  // trace returned flex tokens
	int debug1;  // debug file opening/inclusion
	int debug2;  // debug class definitions and usage
	int debug3;  // debug function definitions and calls
	int debug4;  // debug variable assignments
	int debug5;  // debug constants
	int debug6;  // debug str_prone() results for the input file, instead of parsing it
#endif
	int clist;
	int list;
	int recursive;
	int quiet_if_ok;
	int quiet_if_parse_error;
	int disable_socket;
	int disable_eval;
	int disable_exec;
	int disable_mail;
	int disable_fwrite;
	int disable_obfuscation;
	}
	opt;


/* Per-directory scanning context (extensions and include_path).
   This must be the *exact* same as the start of struct s_opt.
   If not, look for a cast (struct s_dir_opt*)&opt.
*/
extern struct s_dir_opt {
	char extensions[ MAX_EXTENSIONS ][ LEN_EXTENSION+1 ];
	char include_path[ LEN_VSTRING+1 ];
	}
	diropt;


/* Bit masks that state which "...parse" bits are relevant for each
   virus detection type.
*/
extern t_prone prone_masks[ PARSE_VIRUS_NUM ];


/* Data type for bison's yylloc
*/
struct s_file_location {
	const char *filename;
	int include_level;
	int line;
	};


/* PHP value type.
*/
struct s_value {
	t_prone prone;	// one of PRONE_*
	int type;			// one of TYPE_*
	union	{
		double real;
		char string[ LEN_VSTRING+1 ];
		}
		u;
	};


/* PHP variable type.
*/
struct s_var {
	char name[ LEN_VSTRING+1 ];
	int is_global;		// 0 or one of VAR_IS_*
	struct s_value value;
	struct s_var *next[ MAX_NEST ];
		// index 0 for arg_list_*, index 1 for global list
		// remaining indexes for nested function definitions'
		// local variables (superglobals will be linked to
		// every local list, and new superglobals can be set
		// at any time (class properties) so we need all these)
	};


/* PHP function call log.
   Important so that we can log calls even before we see the
   function definition.
*/
struct s_function_call {
	t_prone prone_args;
		// "prone" combination of all calling arguments
		// (used if function isn't defined yet)
	t_prone prone[ PARSE_VIRUS_NUM ];
		// one for each possible virus PARSE_* return value;
		// each states which function arguments could generate this
		// return value;
	struct s_function_call *next;
	};


/* PHP function type.
*/
struct s_function {
	char name   [ LEN_VSTRING+1 ];
	char ofclass[ LEN_VSTRING+1 ];
	int is_defined;  // true (!=0) if we've seen the closing brace of its definiton
	int hard_links;  // determine if function is being redefined recursively (e.g.: bad include() sequence)
	int was_used_before_defined;  // true (!=0) if we've called this function before seeing its definition
	char yylloc_filename[ LEN_PATH+1 ];
	struct s_file_location /*YYLTYPE*/ yylloc;  // location of function definition
	t_prone prone[ PARSE_VIRUS_NUM ];
		// one for each possible virus PARSE_* return value;
		// each states which function arguments can generate this
		// return value;
		// function arguments are determined by the bits in
		// PRONE_FN_ARGS_BITS (bit in PRONE_FN_ARG_0 is the first
		// argument, the one to its left is the second argument,
		// and so on).
	t_prone prone_return;
		// "prone" value for the return value
	struct s_var *vars_local;  // non-NULL only while function is being parsed
	struct s_function_call *calls_first;
	struct s_function_call *calls_last;
	struct s_function *next;
	};


/* Helpful macros
*/
#define min(a,b)	((a) <= (b) ? (a) : (b))
#define max(a,b)	((a) >= (b) ? (a) : (b))
#define array_size(a)	(sizeof(a)/sizeof((a)[0]))


/* Helper functions defined in bea.l */

extern int yy_flex_debug;
extern int yylex( void );

extern void flex_open_file ( const char *file, int once );
extern void flex_close_file( void );
extern void flex_display_file_nest( FILE *fp, int line );
extern void flex_reset_files( void );

/* Helper functions defined in bea.y */

#define YYLTYPE  struct s_file_location

#define YYLLOC_DEFAULT(current, rhs, n)						\
	if( n > 0 )								\
		{								\
		(current).filename      = YYRHSLOC(rhs, 1).filename;		\
		(current).include_level = YYRHSLOC(rhs, 1).include_level;	\
		(current).line          = YYRHSLOC(rhs, 1).line;		\
		}								\
	else									\
		{								\
		(current).filename      = YYRHSLOC(rhs, 0).filename;		\
		(current).include_level = YYRHSLOC(rhs, 0).include_level;	\
		(current).line          = YYRHSLOC(rhs, 0).line;		\
		}

extern int yydebug;
extern int yyparse( void );


/* Helper functions defined in bea-lib.c */

extern char current_namespace [ LEN_VSTRING+1 ];
extern char current_class     [ LEN_VSTRING+1 ];
extern struct s_function *context_fn[ MAX_NEST ];
extern int context_index;
extern int obfuscated_include_found;
extern struct s_file_location obfuscated_include_yylloc;

extern  int yyparse_dir  ( const char *dirname,  const struct s_dir_opt *prev_pdiropt );
extern  int yyparse_file ( const char *filename, const struct s_dir_opt      *pdiropt );
extern void yyparse_reset( void );

extern               void function_start ( const char *fn_name );
extern struct s_function *function_add   ( const char *fn_name, const char *class_name );
extern               void function_end   ( int was_defined );
extern            t_prone fn_call        ( const char *fn_name, const char *class_name, struct s_function_call *pfnc );
extern               void fn_call_arg    ( struct s_function_call *pfnc, int index, t_prone prone );
extern                int fn_call_check  ( int php );
extern               void class_start    ( const char *class_name );
extern               void class_end      ( void );
extern               void namespace_start( const char *space_name );
extern               void namespace_end  ( void );

extern            void var_assign_null    ( const char *name, int prone, int var_is );
extern            void var_assign_obj     ( const char *property, const char *class_name, int prefix_dollar, int prone );
extern            void var_assign         ( const char *name, const struct s_value *pvalue, int var_is );
extern            void var_global_to_local( const char *name, int var_is );
extern            void var_cast           ( struct s_var *pvar, const char *name, int prefix_dollar );
extern            void var_cast_obj       ( struct s_var *pvar, const char *property, const char *class_name, int prefix_dollar );
extern struct s_value *var_get_s_value    ( const char *name, int var_is );
extern             int var_prone          ( const char *name, int var_is );
extern         t_prone str_prone          ( const char *str  );

extern void arg_list_reset( void );
extern void arg_list_apply( t_prone prone );

extern        void s_value_set   ( struct s_value *pvalue, int prone, int type, double real, const char *string );
extern        void s_value_cat   ( struct s_value *pvalue, const char *string );
extern      double s_value_real  ( struct s_value *pvalue );
extern const char* s_value_string( struct s_value *pvalue );
extern const char* unescape_str  ( const char *substring );
#if YYDEBUG
extern void debug_trace( const char *name, const char *class_name, t_prone prone, char type );
#endif
