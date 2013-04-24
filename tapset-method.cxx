// tapset for per-method based probes
// Copyright (C) 2013 Red Hat Inc.

// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "session.h"
#include "tapsets.h"
#include "translate.h"
#include "util.h"
#include "config.h"

#include "unistd.h"
#include "sys/wait.h"
#include "sys/types.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <algorithm>

extern "C" {
#include <fnmatch.h>
}

using namespace std;
using namespace __gnu_cxx;

static const string TOK_CLASS ("class");
static const string TOK_METHOD ("method");
static const string TOK_PROCESS ("process");
static const string TOK_MARK ("mark");
static const string TOK_JAVA ("java");
static const string TOK_RETURN ("return");
static const string TOK_BEGIN ("begin");
static const string TOK_END ("end");
static const string TOK_ERROR ("error");


struct java_builder: public derived_probe_builder
{
private:
  bool cache_initialized;
  typedef multimap<string, string> java_cache_t;
  typedef multimap<string, string>::const_iterator java_cache_const_iterator_t;
  typedef pair<java_cache_const_iterator_t, java_cache_const_iterator_t>
    java_cache_const_iterator_pair_t;
  java_cache_t java_cache;

public:
  java_builder (): cache_initialized (false) {}

  void build (systemtap_session & sess,
	      probe * base,
	      probe_point * location,
	      literal_map_t const & parameters,
	      vector <derived_probe *> & finished_results);

  bool has_null_param (literal_map_t const & params,
		       string const & k);

  bool get_number_param (literal_map_t const & params,
			 string const & k, int & v);
  bool get_param (std::map<std::string, literal*> const & params,
		  const std::string& key,
		  std::string& value);
  std::string mark_param(int i);

};

bool
java_builder::has_null_param(literal_map_t const & params,
			   string const & k)
{
  return derived_probe_builder::has_null_param(params, k);
}

bool
java_builder::get_number_param (literal_map_t const & params,
				string const & k, int & v)
{
  int64_t value;
  bool present = derived_probe_builder::get_param (params, k, value);
  v = (int) value;
  return present;
}

bool
java_builder::get_param (std::map<std::string, literal*> const & params,
                                  const std::string& key,
                                  std::string& value)
{
  map<string, literal *>::const_iterator i = params.find (key);
  if (i == params.end())
    return false;
  literal_string * ls = dynamic_cast<literal_string *>(i->second);
  if (!ls)
    return false;
  value = ls->value;
  return true;
}

std::string
java_builder::mark_param(int i)
{
  switch (i)
    {
    case 0:
      return "method__0";
    case 1:
      return "method__1";
    case 2:
      return "method__2";
    case 3:
      return "method__3";
    case 4:
      return "method__4";
    case 5:
      return "method__5";
    case 6:
      return "method__6";
    case 7:
      return "method__7";
    case 8:
      return "method__8";
    case 9:
      return "method__9";
    case 10:
      return "method__10";
    default:
      return "*";
    }
}

void
java_builder::build (systemtap_session & sess,
		     probe * base,
		     probe_point * loc,
		     literal_map_t const & parameters,
		     vector <derived_probe *> & finished_results)
{
  string method_str_val;
  bool has_method_str = get_param (parameters, TOK_METHOD, method_str_val);
  int short_method_pos = method_str_val.find ('(');
  //only if it exists, run check
  bool one_arg = false; // used to check if there is an argument in the method
  if (short_method_pos)
    {
      int second_method_pos = 0;
      second_method_pos = method_str_val.find (')');
      if ((second_method_pos - short_method_pos) >= 1)
	one_arg = true;
    }
  int _java_pid = 0;
  string _java_proc_class = "";
  string short_method_str = method_str_val.substr (0, short_method_pos);
  string class_str_val; // fully qualified class string
  bool has_class_str = get_param (parameters, TOK_CLASS, class_str_val);
  bool has_pid_int = get_number_param (parameters, TOK_JAVA, _java_pid);
  bool has_pid_str = get_param (parameters, TOK_JAVA, _java_proc_class);
  bool has_return = has_null_param (parameters, TOK_RETURN);

  //need to count the number of parameters, exit if more than 10

  int method_params_count = count (method_str_val.begin (), method_str_val.end (), ',');
  if (one_arg && method_params_count == 0)
    method_params_count++; // in this case we know there was at least a var, but no ','

  if (method_params_count > 10)
    {
      cerr << _("Error: Maximum of 10 method parameters may be specified") << endl;
      return;
    }
  assert (has_method_str);
  (void) has_method_str;
  assert (has_class_str);
  (void) has_class_str;

  const char* java_pid_str;
  if(has_pid_int)
    {
      string _tmp = "";
      _tmp = static_cast <ostringstream*> ( & (ostringstream ()
					       << (_java_pid)))->str ();
      java_pid_str = _tmp.c_str();
    }
  else 
      java_pid_str = _java_proc_class.c_str();

#ifdef HAVE_JAVA_HELPER
  
  if (! (has_pid_int || has_pid_str) )
    exit (1); //XXX proper exit with warning message

  /*
   * while looking at sdt_query::convert_location as an example
   * create a new probe_point*, with same (*base_loc)
   * using a vector, iterate though, changing as needed
   * redefine functor values with new literal_string("foo")
   */

  string helper_location = HAVE_JAVA_HELPER;
  helper_location.append("/libHelperSDT.so");
  probe_point* new_loc = new probe_point(*loc);
  vector<probe_point::component*> java_marker;
  java_marker.push_back( new probe_point::component 
			 (TOK_PROCESS, new literal_string (helper_location)));
  java_marker.push_back( new probe_point::component 
			 (TOK_MARK, new literal_string (mark_param(method_params_count))));
  probe_point * derived_loc = new probe_point (java_marker);

  block *b = new block;
  b->tok = base->body->tok;
  
  // first half of argument
  target_symbol *cc = new target_symbol;
  cc->tok = b->tok;
  cc->name = "$provider";

  functioncall *ccus = new functioncall;
  ccus->function = "user_string";
  ccus->type = pe_string;
  ccus->tok = b->tok;
  ccus->args.push_back(cc);
      
  // second half of argument
  target_symbol *mc = new target_symbol;
  mc->tok = b->tok;
  mc->name = "$name";

  functioncall *mcus = new functioncall;
  mcus->function = "user_string";
  mcus->type = pe_string;
  mcus->tok = b->tok;
  mcus->args.push_back(mc);
      
  //build if statement
  if_statement *ifs = new if_statement;
  ifs->thenblock = new next_statement;
  ifs->elseblock = NULL;
  ifs->tok = b->tok;
  ifs->thenblock->tok = b->tok;

  //class comparison
  comparison *ce = new comparison;
  ce->op = "!=";
  ce->tok = b->tok;
  ce->left = ccus;
  ce->right = new literal_string(class_str_val);
  ce->right->tok = b->tok;

  //method comparision
  comparison *me = new comparison;
  me->op = "!=";
  me->tok = b->tok;
  me->left = mcus;
  me->right = new literal_string(method_str_val);
  me->right->tok = b->tok;

  logical_or_expr *le = new logical_or_expr;
  le->op = "||";
  le->left = ce;
  le->right = me;
  le->tok = b->tok;
  ifs->condition = le;
  b->statements.push_back(ifs);

  b->statements.push_back(base->body);
  base->body = b;

  derived_loc->components = java_marker;
  probe* new_mark_probe = base->create_alias (derived_loc, new_loc);
  derive_probes (sess, new_mark_probe, finished_results);


  //the begin portion of the probe
  vector<probe_point::component*> java_begin_marker;
  java_begin_marker.push_back( new probe_point::component 
  			  (TOK_PROCESS, new literal_string ("/usr/bin/java")));
  java_begin_marker.push_back( new probe_point::component (TOK_BEGIN));

  probe_point * der_begin_loc = new probe_point(java_begin_marker);

  /* stapbm contains the following arguments in a space
     seperated list
     $1 - install/uninstall
     $2 - $STAPTMPDIR
     $3 - PID/unique name
     $4 - RULE name
     $5 - class
     $6 - method
     $7 - number of args
     $8 - entry/exit/line
  */

  char arg_count[3];
  snprintf(arg_count, 3, "%d", method_params_count);
  string new_method = method_str_val;
  size_t string_pos = new_method.find(')', 0);
  while(string_pos != string::npos){
    new_method.insert(int(string_pos), "\\\\");
    string_pos = new_method.find(')',string_pos+4);
  }
  string_pos = new_method.find('(', 0);
  while(string_pos != string::npos){
    new_method.insert(int(string_pos), "\\\\");
    string_pos = new_method.find('(',string_pos+4);
  }

  string stapbm_string = "stapbm ";
  stapbm_string.append("install");
  stapbm_string.append(" ");
  stapbm_string.append(sess.tmpdir);
  stapbm_string.append(" ");
  if (has_pid_int)
    stapbm_string.append(java_pid_str);
  else
    stapbm_string.append(_java_proc_class);
  stapbm_string.append(" ");
  stapbm_string.append(class_str_val + "-" + new_method);
  stapbm_string.append(" ");
  stapbm_string.append(class_str_val);
  stapbm_string.append(" ");
  stapbm_string.append(new_method);
  stapbm_string.append(" ");
  stapbm_string.append(arg_count);
  stapbm_string.append(" ");
  if(!has_return)
    stapbm_string.append("entry");
  else
    stapbm_string.append("exit");
  block *bb = new block;
  bb->tok = base->body->tok;
  functioncall *fc = new functioncall;
  fc->function = "system";
  fc->tok = bb->tok;
  literal_string* num = new literal_string(stapbm_string);
  num->tok = bb->tok;
  fc->args.push_back(num);

  expr_statement* bs = new expr_statement;
  bs->tok = bb->tok;
  bs->value = fc;

  bb->statements.push_back(bs);
  base->body = bb;
  der_begin_loc->components = java_begin_marker;
  probe * bbase = new probe(*base, der_begin_loc);
  probe* new_begin_probe = new probe(*bbase, der_begin_loc);
  derive_probes (sess, new_begin_probe, finished_results);
 
  //the end/error portion of the probe
  vector<probe_point::component*> java_end_marker;
  java_end_marker.push_back( new probe_point::component 
  			  (TOK_PROCESS, new literal_string ("/usr/bin/java")));
  java_end_marker.push_back( new probe_point::component (TOK_END));

  probe_point *der_end_loc = new probe_point (java_end_marker);

  block *eb = new block;
  eb->tok = base->body->tok;
  functioncall *efc = new functioncall;
  efc->function = "system";
  efc->tok = eb->tok;

  string stapbm_remove = "stapbm ";
  stapbm_remove.append("uninstall ");
  stapbm_remove.append(sess.tmpdir);
  stapbm_remove.append(" ");
  if (has_pid_int)
    stapbm_remove.append(java_pid_str);
  else
    stapbm_remove.append(_java_proc_class);
  stapbm_remove.append(" ");
  stapbm_remove.append(class_str_val);
  stapbm_remove.append("-");
  stapbm_remove.append(new_method);

  literal_string* es = new literal_string(stapbm_remove);
  es->tok = eb->tok;
  efc->args.push_back(es);

  expr_statement* ees = new expr_statement;
  ees->tok = eb->tok;
  ees->value = efc;

  eb->statements.push_back(ees);
  base->body = eb;

  der_end_loc->components = java_end_marker;
  probe* ebase = new probe(*base, der_end_loc);
  probe* new_end_probe = new probe(*ebase, der_end_loc);
  derive_probes (sess, new_end_probe, finished_results);

#else
  (void) has_pid_str;
  cerr << _("Cannot probe java method, configure --with-jdk=") << endl;
#endif
}

void
register_tapset_java (systemtap_session& s)
{
  match_node* root = s.pattern_root;
  derived_probe_builder *builder = new java_builder ();

  root->bind_str (TOK_JAVA)
    ->bind_str (TOK_CLASS)->bind_str (TOK_METHOD)
    ->bind(builder);


  root->bind_str (TOK_JAVA)
    ->bind_str (TOK_CLASS)->bind_str (TOK_METHOD)
    ->bind (TOK_RETURN)->bind(builder);

  root->bind_num (TOK_JAVA)
    ->bind_str (TOK_CLASS)->bind_str (TOK_METHOD)
    ->bind (builder);

  root->bind_num (TOK_JAVA)
    ->bind_str (TOK_CLASS)->bind_str (TOK_METHOD)
    ->bind (TOK_RETURN)->bind (builder);

}
