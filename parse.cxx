// recursive descent parser for systemtap scripts
// Copyright (C) 2005-2008 Red Hat Inc.
// Copyright (C) 2006 Intel Corporation.
// Copyright (C) 2007 Bull S.A.S
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "config.h"
#include "staptree.h"
#include "parse.h"
#include "session.h"
#include "util.h"

#include <iostream>
#include <fstream>
#include <cctype>
#include <cstdlib>
#include <cassert>
#include <cerrno>
#include <climits>
#include <sstream>
#include <cstring>
#include <cctype>

using namespace std;

// ------------------------------------------------------------------------



parser::parser (systemtap_session& s, istream& i, bool p):
  session (s),
  input_name ("<input>"), free_input (0),
  input (i, input_name, s), privileged (p),
  context(con_unknown), last_t (0), next_t (0), num_errors (0)
{ }

parser::parser (systemtap_session& s, const string& fn, bool p):
  session (s),
  input_name (fn), free_input (new ifstream (input_name.c_str(), ios::in)),
  input (* free_input, input_name, s), privileged (p),
  context(con_unknown), last_t (0), next_t (0), num_errors (0)
{ }

parser::~parser()
{
  if (free_input) delete free_input;
}


stapfile*
parser::parse (systemtap_session& s, std::istream& i, bool pr)
{
  parser p (s, i, pr);
  return p.parse ();
}


stapfile*
parser::parse (systemtap_session& s, const std::string& n, bool pr)
{
  parser p (s, n, pr);
  return p.parse ();
}

static string
tt2str(token_type tt)
{
  switch (tt)
    {
    case tok_junk: return "junk";
    case tok_identifier: return "identifier";
    case tok_operator: return "operator";
    case tok_string: return "string";
    case tok_number: return "number";
    case tok_embedded: return "embedded-code";
    case tok_keyword: return "keyword";
    }
  return "unknown token";
}

ostream&
operator << (ostream& o, const source_loc& loc)
{
  o << loc.file << ":" 
    << loc.line << ":"
    << loc.column;

  return o;
}

ostream&
operator << (ostream& o, const token& t)
{
  o << tt2str(t.type);

  if (t.type != tok_embedded && t.type != tok_keyword) // XXX: other types?
    {
      o << " '";
      for (unsigned i=0; i<t.content.length(); i++)
        {
          char c = t.content[i];
          o << (isprint (c) ? c : '?');
        }
      o << "'";
    }

  o << " at " 
    << t.location;

  return o;
}


void 
parser::print_error  (const parse_error &pe)
{
  cerr << "parse error: " << pe.what () << endl;

  if (pe.tok)
    {
      cerr << "\tat: " << *pe.tok << endl;
    }
  else
    {
      const token* t = last_t;
      if (t)
        cerr << "\tsaw: " << *t << endl;
      else
        cerr << "\tsaw: " << input_name << " EOF" << endl;
    }

  // XXX: make it possible to print the last input line,
  // so as to line up an arrow with the specific error column

  num_errors ++;
}


const token* 
parser::last ()
{
  return last_t;
}


// Here, we perform on-the-fly preprocessing.
// The basic form is %( CONDITION %? THEN-TOKENS %: ELSE-TOKENS %)
// where CONDITION is: kernel_v[r] COMPARISON-OP "version-string"
//                 or: arch COMPARISON-OP "arch-string"
//                 or: "string1" COMPARISON-OP "string2"
//                 or: number1 COMPARISON-OP number2
// The %: ELSE-TOKENS part is optional.
//
// e.g. %( kernel_v > "2.5" %? "foo" %: "baz" %)
// e.g. %( arch != "i686" %? "foo" %: "baz" %)
//
// Up to an entire %( ... %) expression is processed by a single call
// to this function.  Tokens included by any nested conditions are
// enqueued in a private vector.

bool eval_pp_conditional (systemtap_session& s,
                          const token* l, const token* op, const token* r)
{
  if (l->type == tok_identifier && (l->content == "kernel_v" ||
                                    l->content == "kernel_vr"))
    {
      string target_kernel_vr = s.kernel_release;
      string target_kernel_v = s.kernel_base_release;
      
      if (! (r->type == tok_string))
        throw parse_error ("expected string literal", r);
      string query_kernel_vr = r->content;
      
      // collect acceptable strverscmp results.
      int rvc_ok1, rvc_ok2;
      if (op->type == tok_operator && op->content == "<=")
        { rvc_ok1 = -1; rvc_ok2 = 0; }
      else if (op->type == tok_operator && op->content == ">=")
        { rvc_ok1 = 1; rvc_ok2 = 0; }
      else if (op->type == tok_operator && op->content == "<")
        { rvc_ok1 = -1; rvc_ok2 = -1; }
      else if (op->type == tok_operator && op->content == ">")
        { rvc_ok1 = 1; rvc_ok2 = 1; }
      else if (op->type == tok_operator && op->content == "==")
        { rvc_ok1 = 0; rvc_ok2 = 0; }
      else if (op->type == tok_operator && op->content == "!=")
        { rvc_ok1 = -1; rvc_ok2 = 1; }
      else
        throw parse_error ("expected comparison operator", op);
      
      int rvc_result = strverscmp ((l->content == "kernel_vr" ? 
                                    target_kernel_vr.c_str() :
                                    target_kernel_v.c_str()),
                                   query_kernel_vr.c_str());
      // normalize rvc_result
      if (rvc_result < 0) rvc_result = -1;
      if (rvc_result > 0) rvc_result = 1;
      
      return (rvc_result == rvc_ok1 || rvc_result == rvc_ok2);
    }
  else if (l->type == tok_identifier && l->content == "arch")
    {
      string target_architecture = s.architecture;
      if (! (r->type == tok_string))
        throw parse_error ("expected string literal", r);
      string query_architecture = r->content;
      
      bool result;
      if (op->type == tok_operator && op->content == "==")
        result = target_architecture == query_architecture;
      else if (op->type == tok_operator && op->content == "!=")
        result = target_architecture != query_architecture;
      else
        throw parse_error ("expected '==' or '!='", op);
      
      return result;
    }  
  else if ((l->type == tok_string && r->type == tok_string)
	   || (l->type == tok_number && r->type == tok_number))
    {
      // collect acceptable strverscmp results.
      int rvc_ok1, rvc_ok2;
      if (op->type == tok_operator && op->content == "<=")
        { rvc_ok1 = -1; rvc_ok2 = 0; }
      else if (op->type == tok_operator && op->content == ">=")
        { rvc_ok1 = 1; rvc_ok2 = 0; }
      else if (op->type == tok_operator && op->content == "<")
        { rvc_ok1 = -1; rvc_ok2 = -1; }
      else if (op->type == tok_operator && op->content == ">")
        { rvc_ok1 = 1; rvc_ok2 = 1; }
      else if (op->type == tok_operator && op->content == "==")
        { rvc_ok1 = 0; rvc_ok2 = 0; }
      else if (op->type == tok_operator && op->content == "!=")
        { rvc_ok1 = -1; rvc_ok2 = 1; }
      else
        throw parse_error ("expected comparison operator", op);

      int rvc_result = l->content.compare(r->content);

      // normalize rvc_result
      if (rvc_result < 0) rvc_result = -1;
      if (rvc_result > 0) rvc_result = 1;

      return (rvc_result == rvc_ok1 || rvc_result == rvc_ok2);
    }
  else if (l->type == tok_string && r->type == tok_number
	    && op->type == tok_operator)
    throw parse_error ("expected string literal as right value", r);
  else if (l->type == tok_number && r->type == tok_string
	    && op->type == tok_operator)
    throw parse_error ("expected number literal as right value", r);
  // XXX: support other forms?  "CONFIG_SMP" ?
  else
    throw parse_error ("expected 'arch' or 'kernel_v' or 'kernel_vr'\n"
		       "             or comparison between strings or integers", l);
}


// expand_args is used to know if we must expand $x and @x identifiers.
// Only tokens corresponding to the TRUE statement must be expanded
const token*
parser::scan_pp (bool wildcard, bool expand_args)
{
  while (true)
    {
      if (enqueued_pp.size() > 0)
        {
          const token* t = enqueued_pp[0];
          enqueued_pp.erase (enqueued_pp.begin());
          return t;
        }

      const token* t = input.scan (wildcard, expand_args); // NB: not recursive!
      if (t == 0) // EOF
        return t;
      
      if (! (t->type == tok_operator && t->content == "%(")) // ordinary token
        return t;

      // We have a %( - it's time to throw a preprocessing party!

      const token *l, *op, *r;
      l = input.scan (false, expand_args); // NB: not recursive, though perhaps could be
      op = input.scan (false, expand_args);
      r = input.scan (false, expand_args);
      if (l == 0 || op == 0 || r == 0)
        throw parse_error ("incomplete condition after '%('", t);
      // NB: consider generalizing to consume all tokens until %?, and
      // passing that as a vector to an evaluator.

      // Do not evaluate the condition if we haven't expanded everything.
      // This may occured when having several recursive conditionals.
      bool result = expand_args && eval_pp_conditional (session, l, op, r);
      delete l;
      delete op;
      delete r;
      
      const token *m = input.scan (); // NB: not recursive
      if (! (m && m->type == tok_operator && m->content == "%?"))
        throw parse_error ("expected '%?' marker for conditional", t);
      delete m; // "%?"

      vector<const token*> my_enqueued_pp;
      bool have_token = false;
      
      while (true) // consume THEN tokens
        {
          m = scan_pp (wildcard, result); // NB: recursive
          if (m == 0)
            throw parse_error (have_token ?
                               "incomplete conditional - missing %: or %)" :
                               "missing THEN tokens for conditional",
                               t);

	  have_token = true;
          if (m->type == tok_operator && (m->content == "%:" || // ELSE
                                          m->content == "%)")) // END
            break;
          // enqueue token
          if (result) 
            my_enqueued_pp.push_back (m);
          else
            delete m; // unused token
          // continue
        }
      
      have_token = false;
      if (m && m->type == tok_operator && m->content == "%:") // ELSE
        {
          delete m; // "%:"
          while (true)
            {
              m = scan_pp (wildcard, expand_args && !result); // NB: recursive
              if (m == 0)
		  throw parse_error (have_token ?
                                     "incomplete conditional - missing %)" :
                                     "missing ELSE tokens for conditional",
                                     t);

	      have_token = true;
              if (m->type == tok_operator && m->content == "%)") // END
                break;
              // enqueue token
              if (! result) 
                my_enqueued_pp.push_back (m);
              else
                delete m; // unused token
              // continue
            }
        }
      delete t; // "%("
      delete m; // "%)"

      // NB: we transcribe the retained tokens here, and not inside
      // the THEN/ELSE while loops.  If it were done there, each loop
      // would become infinite (each iteration consuming an ordinary
      // token the previous one just pushed there).  Guess how I
      // figured that out.
      enqueued_pp.insert (enqueued_pp.end(),
                          my_enqueued_pp.begin(),
                          my_enqueued_pp.end());

      // Go back to outermost while(true) loop.  We hope that at least
      // some THEN or ELSE tokens were enqueued.  If not, around we go
      // again, until EOF.
    }
}


const token*
parser::next (bool wildcard)
{
  if (! next_t)
    next_t = scan_pp (wildcard);
  if (! next_t)
    throw parse_error ("unexpected end-of-file");

  last_t = next_t;
  // advance by zeroing next_t
  next_t = 0;
  return last_t;
}


const token*
parser::peek (bool wildcard)
{
  if (! next_t)
    next_t = scan_pp (wildcard);

  // don't advance by zeroing next_t
  last_t = next_t;
  return next_t;
}


static inline bool
tok_is(token const * t, token_type tt, string const & expected)
{
  return t && t->type == tt && t->content == expected;
}


const token* 
parser::expect_known (token_type tt, string const & expected)
{
  const token *t = next();
  if (! (t && t->type == tt && t->content == expected))
    throw parse_error ("expected '" + expected + "'");
  return t;
}


const token* 
parser::expect_unknown (token_type tt, string & target)
{
  const token *t = next();
  if (!(t && t->type == tt))
    throw parse_error ("expected " + tt2str(tt));
  target = t->content;
  return t;
}


const token* 
parser::expect_unknown2 (token_type tt1, token_type tt2, string & target)
{
  const token *t = next();
  if (!(t && (t->type == tt1 || t->type == tt2)))
    throw parse_error ("expected " + tt2str(tt1) + " or " + tt2str(tt2));
  target = t->content;
  return t;
}


const token* 
parser::expect_op (std::string const & expected)
{
  return expect_known (tok_operator, expected);
}


const token* 
parser::expect_kw (std::string const & expected)
{
  return expect_known (tok_identifier, expected);
}

const token* 
parser::expect_number (int64_t & value)
{
  bool neg = false;
  const token *t = next();
  if (t->type == tok_operator && t->content == "-")
    {
      neg = true;
      t = next ();
    }
  if (!(t && t->type == tok_number))
    throw parse_error ("expected number");

  const char* startp = t->content.c_str ();
  char* endp = (char*) startp;

  // NB: we allow controlled overflow from LLONG_MIN .. ULLONG_MAX
  // Actually, this allows all the way from -ULLONG_MAX to ULLONG_MAX,
  // since the lexer only gives us positive digit strings, but we'll
  // limit it to LLONG_MIN when a '-' operator is fed into the literal.
  errno = 0;
  value = (int64_t) strtoull (startp, & endp, 0);
  if (errno == ERANGE || errno == EINVAL || *endp != '\0'
      || (neg && (unsigned long long) value > 9223372036854775808ULL)
      || (unsigned long long) value > 18446744073709551615ULL
      || value < -9223372036854775807LL-1)
    throw parse_error ("number invalid or out of range"); 
  
  if (neg)
    value = -value;

  return t;
}


const token* 
parser::expect_ident (std::string & target)
{
  return expect_unknown (tok_identifier, target);
}


const token* 
parser::expect_ident_or_keyword (std::string & target)
{
  return expect_unknown2 (tok_identifier, tok_keyword, target);
}


bool 
parser::peek_op (std::string const & op)
{
  return tok_is (peek(), tok_operator, op);
}


bool 
parser::peek_kw (std::string const & kw)
{
  return tok_is (peek(), tok_identifier, kw);
}



lexer::lexer (istream& i, const string& in, systemtap_session& s):
  input (i), input_name (in), cursor_suspend_count(0), 
  cursor_line (1), cursor_column (1), session(s)
{ }


int
lexer::input_peek (unsigned n)
{
  while (lookahead.size() <= n)
    {
      int c = input.get ();
      lookahead.push_back (input ? c : -1);
    }
  return lookahead[n];
}


int 
lexer::input_get ()
{
  int c = input_peek (0);
  lookahead.erase (lookahead.begin ());

  if (c < 0) return c; // EOF

  if (cursor_suspend_count)
    // Track effect of input_put: preserve previous cursor/line_column
    // until all of its characters are consumed.
    cursor_suspend_count --;
  else
    {
      // update source cursor
      if (c == '\n')
        {
          cursor_line ++;
          cursor_column = 1;
        }
      else
        cursor_column ++;
    }

  return c;
}


void
lexer::input_put (const string& chars)
{
  // clog << "[put:" << chars << "]";
  for (int i=chars.size()-1; i>=0; i--)
    {
      int c = chars[i];
      lookahead.insert (lookahead.begin(), c);
      cursor_suspend_count ++;
    }
}


token*
lexer::scan (bool wildcard, bool expand_args)
{
  token* n = new token;
  n->location.file = input_name;

  unsigned semiskipped_p = 0;

 skip:
  n->location.line = cursor_line;
  n->location.column = cursor_column;

 semiskip:
  if (semiskipped_p > 1)
    {
      input_get ();
      throw parse_error ("invalid nested substitution of command line arguments");
    }

  int c = input_get();
  int c2 = input_peek ();
  // clog << "{" << (char)c << (char)c2 << "}";
  if (c < 0)
    {
      delete n;
      return 0;
    }

  if (isspace (c))
    goto skip;

  // Paste command line arguments as character streams into
  // the beginning of a token.  $1..$999 go through as raw
  // characters; @1..@999 are quoted/escaped as strings.
  // $# and @# expand to the number of arguments, similarly
  // raw or quoted.
  if (expand_args &&
      (c == '$' || c == '@') &&
      (c2 == '#'))
    {
      input_get(); // swallow '#'
      stringstream converter;
      converter << session.args.size ();
      if (c == '$') input_put (converter.str());
      else input_put (lex_cast_qstring (converter.str()));
      semiskipped_p ++;
      goto semiskip;
    }
  else if (expand_args &&
           (c == '$' || c == '@') &&
           (isdigit (c2)))
    {
      unsigned idx = 0;
      do
        {
          input_get ();
          idx = (idx * 10) + (c2 - '0');
          c2 = input_peek ();
        } while (c2 > 0 &&
                 isdigit (c2) && 
                 idx <= session.args.size()); // prevent overflow
      if (idx == 0 ||
          idx-1 >= session.args.size())
          throw parse_error ("command line argument index invalid or out of range", n);

      string arg = session.args[idx-1];
      if (c == '$') input_put (arg);
      else input_put (lex_cast_qstring (arg));
      semiskipped_p ++;
      goto semiskip;
    }

  else if (isalpha (c) || c == '$'
	   || (c == '@' && c2 != '@') // XXX: what identifiers use @foobar?
	   || c == '_' || (wildcard && c == '*'))
    {
      n->type = tok_identifier;
      n->content = (char) c;
      while (isalnum (c2) || c2 == '_' || c2 == '$' ||
	     (wildcard && c2 == '*'))
	{
          input_get ();
          n->content.push_back (c2);
          c2 = input_peek ();
        }

      if (n->content    == "probe"
          || n->content == "global"
          || n->content == "function"
          || n->content == "if"
          || n->content == "else"
          || n->content == "for"
          || n->content == "foreach"
          || n->content == "in"
          || n->content == "limit"
          || n->content == "return"
          || n->content == "delete"
          || n->content == "while"
          || n->content == "break"
          || n->content == "continue"
          || n->content == "next"
          || n->content == "string"
          || n->content == "long")
        n->type = tok_keyword;
      
      return n;
    }

  else if (isdigit (c)) // positive literal
    {
      n->type = tok_number;
      n->content = (char) c;

      while (1)
	{
	  int c2 = input_peek ();
	  if (c2 < 0)
	    break;

          // NB: isalnum is very permissive.  We rely on strtol, called in
          // parser::parse_literal below, to confirm that the number string
          // is correctly formatted and in range.

	  if (isalnum (c2))
	    {
	      n->content.push_back (c2);
	      input_get ();
	    }
	  else
	    break;
	}
      return n;
    }

  else if (c == '\"')
    {
      n->type = tok_string;
      while (1)
	{
	  c = input_get ();

	  if (c < 0 || c == '\n')
	    {
	      n->type = tok_junk;
	      break;
	    }
	  if (c == '\"') // closing double-quotes
	    break;
	  else if (c == '\\') // see also input_put
	    {	      
	      c = input_get ();
	      switch (c)
		{
		case 'a':
		case 'b':
		case 't':
		case 'n':
		case 'v':
		case 'f':
		case 'r':
		case '0' ... '7': // NB: need only match the first digit
		case '\\':
		  // Pass these escapes through to the string value
		  // being parsed; it will be emitted into a C literal. 

		  n->content.push_back('\\');

                  // fall through
		default:
		  n->content.push_back(c);
		  break;
		}
	    }
	  else
	    n->content.push_back(c);
	}
      return n;
    }

  else if (ispunct (c))
    {
      int c2 = input_peek ();
      int c3 = input_peek (1);
      string s1 = string("") + (char) c;
      string s2 = (c2 > 0 ? s1 + (char) c2 : s1);
      string s3 = (c3 > 0 ? s2 + (char) c3 : s2);

      // NB: if we were to recognize negative numeric literals here,
      // we'd introduce another grammar ambiguity:
      // 1-1 would be parsed as tok_number(1) and tok_number(-1)
      // instead of tok_number(1) tok_operator('-') tok_number(1)

      if (s1 == "#") // shell comment
        {
          unsigned this_line = cursor_line;
          do { c = input_get (); }
          while (c >= 0 && cursor_line == this_line);
          goto skip;
        }
      else if (s2 == "//") // C++ comment
        {
          unsigned this_line = cursor_line;
          do { c = input_get (); }
          while (c >= 0 && cursor_line == this_line);
          goto skip;
        }
      else if (c == '/' && c2 == '*') // C comment
	{
          c2 = input_get ();
          unsigned chars = 0;
          while (c2 >= 0)
            {
              chars ++; // track this to prevent "/*/" from being accepted
              c = c2;
              c2 = input_get ();
              if (chars > 1 && c == '*' && c2 == '/')
                break;
            }
          goto skip;
	}
      else if (c == '%' && c2 == '{') // embedded code
        {
          n->type = tok_embedded;
          (void) input_get (); // swallow '{' already in c2
          while (true)
            {
              c = input_get ();
              if (c < 0) // EOF
                {
                  n->type = tok_junk;
                  break;
                }
              if (c == '%')
                {
                  c2 = input_peek ();
                  if (c2 == '}')
                    {
                      (void) input_get (); // swallow '}' too
                      break;
                    }
                }
              n->content += c;
            }
          return n;
        }

      // We're committed to recognizing at least the first character
      // as an operator.
      n->type = tok_operator;

      // match all valid operators, in decreasing size order
      if (s3 == "<<<" ||
          s3 == "<<=" ||
          s3 == ">>=")
        {
          n->content = s3;
          input_get (); input_get (); // swallow other two characters
        }
      else if (s2 == "==" ||
               s2 == "!=" ||
               s2 == "<=" ||
               s2 == ">=" ||
               s2 == "+=" ||
               s2 == "-=" ||
               s2 == "*=" ||
               s2 == "/=" ||
               s2 == "%=" ||
               s2 == "&=" ||
               s2 == "^=" ||
               s2 == "|=" ||
               s2 == ".=" ||
               s2 == "&&" ||
               s2 == "||" ||
               s2 == "++" ||
               s2 == "--" ||
               s2 == "->" ||
               s2 == "<<" ||
               s2 == ">>" ||
               s2 == "@@" ||
               // preprocessor tokens
               s2 == "%(" ||
               s2 == "%?" ||
               s2 == "%:" ||
               s2 == "%)")
        {
          n->content = s2;
          input_get (); // swallow other character
        }   
      else
        {
          n->content = s1;
        }

      return n;
    }

  else
    {
      n->type = tok_junk;
      n->content = (char) c;
      return n;
    }
}


// ------------------------------------------------------------------------

stapfile*
parser::parse ()
{
  stapfile* f = new stapfile;
  f->name = input_name;

  while (1)
    {
      try
	{
	  const token* t = peek ();
	  if (! t) // nice clean EOF
	    break;

	  if (t->type == tok_keyword && t->content == "probe")
	    {
	      context = con_probe;
	      parse_probe (f->probes, f->aliases);
	    }
	  else if (t->type == tok_keyword && t->content == "global")
	    {
	      context = con_global;
	      parse_global (f->globals, f->probes);
	    }
	  else if (t->type == tok_keyword && t->content == "function")
	    {
	      context = con_function;
	      parse_functiondecl (f->functions);
	    }
          else if (t->type == tok_embedded)
	    {
	      context = con_embedded;
	      f->embeds.push_back (parse_embeddedcode ());
	    }
	  else
	    {
	      context = con_unknown;
	      throw parse_error ("expected 'probe', 'global', 'function', or '%{'");
	    }
	}
      catch (parse_error& pe)
	{
	  print_error (pe);
          if (pe.skip_some) // for recovery
            try 
              {
                // Quietly swallow all tokens until the next '}'.
                while (1)
                  {
                    const token* t = peek ();
                    if (! t)
                      break;
                    next ();
                    if (t->type == tok_operator && t->content == "}")
                      break;
                  }
              }
            catch (parse_error& pe2)
              {
                // parse error during recovery ... ugh
                print_error (pe2);
              }
        }
    }

  if (num_errors > 0)
    {
      cerr << num_errors << " parse error(s)." << endl;
      delete f;
      return 0;
    }
  
  return f;
}


void
parser::parse_probe (std::vector<probe *> & probe_ret,
		     std::vector<probe_alias *> & alias_ret)
{
  const token* t0 = next ();
  if (! (t0->type == tok_keyword && t0->content == "probe"))
    throw parse_error ("expected 'probe'");

  vector<probe_point *> aliases;
  vector<probe_point *> locations;

  bool equals_ok = true;
  string docstr;
  int epilogue_alias = 0;

  while (1)
    {
      probe_point * pp = parse_probe_point ();
      
      const token* t = peek ();
      if (equals_ok && t 
          && t->type == tok_operator && t->content == "=")
        {
          aliases.push_back(pp);
          next ();
          continue;
        }
      else if (equals_ok && t 
          && t->type == tok_operator && t->content == "+=")
        {
          aliases.push_back(pp);
          epilogue_alias = 1;
          next ();
          continue;
        }
      else if (t && t->type == tok_operator && t->content == ",")
        {
          locations.push_back(pp);
          equals_ok = false;
          next ();
          continue;
        }
      else if (t && t->type == tok_operator && t->content == "@@")
	{
	  do
	    { // consume consecutive @@ "foo bar" docstrings
	      next (); // swallow @@ itself
	      const token* t1 = next (); 
	      if (! (t1 && t1->type == tok_string))
		throw parse_error ("expected documentation string");
	      if (docstr != "") docstr += "\\n";
	      docstr += t1->content;
	      t = peek ();
	    } 
	  while (t && t->type == tok_operator && t->content == "@@");
	  // fall through
	}
      if (t && t->type == tok_operator && t->content == "{")
        {
          locations.push_back(pp);
          break;
        }
      else
	throw parse_error ("expected probe point specifier");
    }

  if (aliases.empty())
    {
      probe* p = new probe;
      p->tok = t0;
      p->locations = locations;
      p->body = parse_stmt_block ();
      p->privileged = privileged;
      p->docstr = docstr;
      probe_ret.push_back (p);
    }
  else
    {
      probe_alias* p = new probe_alias (aliases);
      p->epilogue_style = epilogue_alias;
      p->tok = t0;
      p->locations = locations;
      p->docstr = docstr;
      p->body = parse_stmt_block ();
      p->privileged = privileged;
      alias_ret.push_back (p);
    }
}


embeddedcode*
parser::parse_embeddedcode ()
{
  embeddedcode* e = new embeddedcode;
  const token* t = next ();
  if (t->type != tok_embedded)
    throw parse_error ("expected '%{'");

  if (! privileged)
    throw parse_error ("embedded code in unprivileged script",
                       false /* don't skip tokens for parse resumption */);

  e->tok = t;
  e->code = t->content;
  return e;
}


block*
parser::parse_stmt_block ()
{
  block* pb = new block;

  const token* t = next ();
  if (! (t->type == tok_operator && t->content == "{"))
    throw parse_error ("expected '{'");

  pb->tok = t;

  while (1)
    {
      try
	{
	  t = peek ();
	  if (t && t->type == tok_operator && t->content == "}")
	    {
	      next ();
	      break;
	    }

          pb->statements.push_back (parse_statement ());
	}
      catch (parse_error& pe)
	{
	  print_error (pe);

	  // Quietly swallow all tokens until the next ';' or '}'.
	  while (1)
	    {
	      const token* t = peek ();
	      if (! t) return 0;
	      next ();
	      if (t->type == tok_operator
                  && (t->content == "}" || t->content == ";"))
		break;
	    }
	}
    }

  return pb;
}


statement*
parser::parse_statement ()
{
  const token* t = peek ();
  if (t && t->type == tok_operator && t->content == ";")
    {
      null_statement* n = new null_statement ();
      n->tok = next ();
      return n;
    }
  else if (t && t->type == tok_operator && t->content == "{")  
    return parse_stmt_block ();
  else if (t && t->type == tok_keyword && t->content == "if")
    return parse_if_statement ();
  else if (t && t->type == tok_keyword && t->content == "for")
    return parse_for_loop ();
  else if (t && t->type == tok_keyword && t->content == "foreach")
    return parse_foreach_loop ();
  else if (t && t->type == tok_keyword && t->content == "return")
    return parse_return_statement ();
  else if (t && t->type == tok_keyword && t->content == "delete")
    return parse_delete_statement ();
  else if (t && t->type == tok_keyword && t->content == "while")
    return parse_while_loop ();
  else if (t && t->type == tok_keyword && t->content == "break")
    return parse_break_statement ();
  else if (t && t->type == tok_keyword && t->content == "continue")
    return parse_continue_statement ();
  else if (t && t->type == tok_keyword && t->content == "next")
    return parse_next_statement ();
  // XXX: "do/while" statement?
  else if (t && (t->type == tok_operator || // expressions are flexible
                 t->type == tok_identifier ||
                 t->type == tok_number ||
                 t->type == tok_string))
    return parse_expr_statement ();
  // XXX: consider generally accepting tok_embedded here too
  else
    throw parse_error ("expected statement");
}


void
parser::parse_global (vector <vardecl*>& globals, vector<probe*>&)
{
  const token* t0 = next ();
  if (! (t0->type == tok_keyword && t0->content == "global"))
    throw parse_error ("expected 'global'");

  while (1)
    {
      const token* t = next ();
      if (! (t->type == tok_identifier))
        throw parse_error ("expected identifier");

      for (unsigned i=0; i<globals.size(); i++)
	if (globals[i]->name == t->content)
	  throw parse_error ("duplicate global name");
      
      vardecl* d = new vardecl;
      d->name = t->content;
      d->tok = t;
      globals.push_back (d);

      t = peek ();

      if (t && t->type == tok_operator && t->content == "[") // array size
	{
	  int64_t size;
	  next ();
	  expect_number(size);
	  if (size <= 0 || size > 1000000) // arbitrary max
	    throw parse_error("array size out of range");
	  d->maxsize = (int)size;
	  expect_known(tok_operator, "]");
	  t = peek ();
	}

      if (t && t->type == tok_operator && t->content == "=") // initialization
	{
	  if (!d->compatible_arity(0))
	    throw parse_error("only scalar globals can be initialized");
	  d->set_arity(0);
	  next ();
	  d->init = parse_literal ();
	  d->type = d->init->type;
	  t = peek ();
	}

      if (t && t->type == tok_operator && t->content == "@@")
	{
	  do
	    { // consume consecutive @@ "foo bar" docstrings
	      next (); // swallow @@ itself
	      const token* t1 = next (); 
	      if (! (t1 && t1->type == tok_string))
		throw parse_error ("expected documentation string");
	      if (d->docstr != "") d->docstr += "\\n";
	      d->docstr += t1->content;
	      t = peek ();
	    } 
	  while (t && t->type == tok_operator && t->content == "@@");
	}
      
      if (t && t->type == tok_operator && t->content == ",") // next global
	{
	  next ();
	  continue;
	}
      else
	break;
    }
}


void
parser::parse_functiondecl (std::vector<functiondecl*>& functions)
{
  const token* t = next ();
  if (! (t->type == tok_keyword && t->content == "function"))
    throw parse_error ("expected 'function'");


  t = next ();
  if (! (t->type == tok_identifier)
      && ! (t->type == tok_keyword
	    && (t->content == "string" || t->content == "long")))
    throw parse_error ("expected identifier");

  for (unsigned i=0; i<functions.size(); i++)
    if (functions[i]->name == t->content)
      throw parse_error ("duplicate function name");

  functiondecl *fd = new functiondecl ();
  fd->name = t->content;
  fd->tok = t;

  t = next ();
  if (t->type == tok_operator && t->content == ":")
    {
      t = next ();
      if (t->type == tok_keyword && t->content == "string")
	fd->type = pe_string;
      else if (t->type == tok_keyword && t->content == "long")
	fd->type = pe_long;
      else throw parse_error ("expected 'string' or 'long'");

      t = next ();
    }

  if (t && t->type == tok_operator && t->content == "@@")
    {
      do
	{ // consume consecutive @@ "foo bar" docstrings
	  // next (); // @@ itself is already swallowed
	  const token* t1 = next (); 
	  if (! (t1 && t1->type == tok_string))
	    throw parse_error ("expected documentation string");
	  if (fd->docstr != "") fd->docstr += "\\n";
	  fd->docstr += t1->content;
	  t = next ();
	} 
      while (t && t->type == tok_operator && t->content == "@@");
    }

  if (! (t->type == tok_operator && t->content == "("))
    throw parse_error ("expected '('");

  while (1)
    {
      t = next ();

      // permit zero-argument fuctions
      if (t->type == tok_operator && t->content == ")")
        break;
      else if (! (t->type == tok_identifier))
	throw parse_error ("expected identifier");
      vardecl* vd = new vardecl;
      vd->name = t->content;
      vd->tok = t;
      fd->formal_args.push_back (vd);

      t = next ();
      if (t->type == tok_operator && t->content == ":")
	{
	  t = next ();
	  if (t->type == tok_keyword && t->content == "string")
	    vd->type = pe_string;
	  else if (t->type == tok_keyword && t->content == "long")
	    vd->type = pe_long;
	  else throw parse_error ("expected 'string' or 'long'");
	  
	  t = next ();
	}
      
      if (t && t->type == tok_operator && t->content == "@@")
	{
	  do
	    { // consume consecutive @@ "foo bar" docstrings
	      // next (); @@ itself is already swallowed
	      const token* t1 = next (); 
	      if (! (t1 && t1->type == tok_string))
		throw parse_error ("expected documentation string");
	      if (vd->docstr != "") vd->docstr += "\\n";
	      vd->docstr += t1->content;
	      t = next ();
	    } 
	  while (t && t->type == tok_operator && t->content == "@@");
	}
      
      if (t->type == tok_operator && t->content == ")")
	break;
      if (t->type == tok_operator && t->content == ",")
	continue;
      else
	throw parse_error ("expected ',' or ')'");
    }

  t = peek ();
  if (t && t->type == tok_embedded)
    fd->body = parse_embeddedcode ();
  else
    fd->body = parse_stmt_block ();

  functions.push_back (fd);
}


probe_point*
parser::parse_probe_point ()
{
  probe_point* pl = new probe_point;

  while (1)
    {
      const token* t = next (true); // wildcard scanning here
      if (! (t->type == tok_identifier
	     // we must allow ".return" and ".function", which are keywords
	     || t->type == tok_keyword))
        throw parse_error ("expected identifier or '*'");

      if (pl->tok == 0) pl->tok = t;

      probe_point::component* c = new probe_point::component;
      c->functor = t->content;
      pl->components.push_back (c);
      // NB we may add c->arg soon

      t = peek ();

      // consume optional parameter
      if (t && t->type == tok_operator && t->content == "(")
        {
          next (); // consume "("
          c->arg = parse_literal ();

          t = next ();
          if (! (t->type == tok_operator && t->content == ")"))
            throw parse_error ("expected ')'");

          t = peek ();
        }

      if (t && t->type == tok_operator && t->content == ".")
        {
          next ();
          continue;
        }

      // We only fall through here at the end of a probe point (past
      // all the dotted/parametrized components).

      if (t && t->type == tok_operator &&
          (t->content == "?" || t->content == "!"))
        {
          pl->optional = true;
          if (t->content == "!") pl->sufficient = true;
          // NB: sufficient implies optional
          next ();
          t = peek ();
          // fall through
        }

      if (t && t->type == tok_keyword && t->content == "if")
        {
          next ();
          t = peek ();
          if (t && ! (t->type == tok_operator && t->content == "("))
            throw parse_error ("expected '('");
          next ();

          pl->condition = parse_expression ();

          t = peek ();
          if (t && ! (t->type == tok_operator && t->content == ")"))
            throw parse_error ("expected ')'");
          next ();
          t = peek ();
          // fall through
        }

      if (t && t->type == tok_operator 
          && (t->content == "{" || t->content == "," ||
              t->content == "=" || t->content == "+=" ||
	      t->content == "@@"))
        break;
      
      throw parse_error ("expected one of '. , ( ? ! { = += @@'");
    }

  return pl;
}


literal*
parser::parse_literal ()
{
  const token* t = next ();
  literal* l;
  if (t->type == tok_string)
    l = new literal_string (t->content);
  else
    {
      bool neg = false;
      if (t->type == tok_operator && t->content == "-")
	{
	  neg = true;
	  t = next ();
	}

      if (t->type == tok_number)
	{
	  const char* startp = t->content.c_str ();
	  char* endp = (char*) startp;

	  // NB: we allow controlled overflow from LLONG_MIN .. ULLONG_MAX
	  // Actually, this allows all the way from -ULLONG_MAX to ULLONG_MAX,
	  // since the lexer only gives us positive digit strings, but we'll
	  // limit it to LLONG_MIN when a '-' operator is fed into the literal.
	  errno = 0;
	  long long value = (long long) strtoull (startp, & endp, 0);
	  if (errno == ERANGE || errno == EINVAL || *endp != '\0'
	      || (neg && (unsigned long long) value > 9223372036854775808ULL)
	      || (unsigned long long) value > 18446744073709551615ULL
	      || value < -9223372036854775807LL-1)
	    throw parse_error ("number invalid or out of range"); 

	  if (neg)
	    value = -value;

	  l = new literal_number (value);
	}
      else
	throw parse_error ("expected literal string or number");
    }

  l->tok = t;
  return l;
}


if_statement*
parser::parse_if_statement ()
{
  const token* t = next ();
  if (! (t->type == tok_keyword && t->content == "if"))
    throw parse_error ("expected 'if'");
  if_statement* s = new if_statement;
  s->tok = t;

  t = next ();
  if (! (t->type == tok_operator && t->content == "("))
    throw parse_error ("expected '('");

  s->condition = parse_expression ();

  t = next ();
  if (! (t->type == tok_operator && t->content == ")"))
    throw parse_error ("expected ')'");

  s->thenblock = parse_statement ();

  t = peek ();
  if (t && t->type == tok_keyword && t->content == "else")
    {
      next ();
      s->elseblock = parse_statement ();
    }
  else
    s->elseblock = 0; // in case not otherwise initialized

  return s;
}


expr_statement*
parser::parse_expr_statement ()
{
  expr_statement *es = new expr_statement;
  const token* t = peek ();
  es->tok = t;
  es->value = parse_expression ();
  return es;
}


return_statement*
parser::parse_return_statement ()
{
  const token* t = next ();
  if (! (t->type == tok_keyword && t->content == "return"))
    throw parse_error ("expected 'return'");
  if (context != con_function)
    throw parse_error ("found 'return' not in function context");
  return_statement* s = new return_statement;
  s->tok = t;
  s->value = parse_expression ();
  return s;
}


delete_statement*
parser::parse_delete_statement ()
{
  const token* t = next ();
  if (! (t->type == tok_keyword && t->content == "delete"))
    throw parse_error ("expected 'delete'");
  delete_statement* s = new delete_statement;
  s->tok = t;
  s->value = parse_expression ();
  return s;
}


next_statement*
parser::parse_next_statement ()
{
  const token* t = next ();
  if (! (t->type == tok_keyword && t->content == "next"))
    throw parse_error ("expected 'next'");
  if (context != con_probe)
    throw parse_error ("found 'next' not in probe context");
  next_statement* s = new next_statement;
  s->tok = t;
  return s;
}


break_statement*
parser::parse_break_statement ()
{
  const token* t = next ();
  if (! (t->type == tok_keyword && t->content == "break"))
    throw parse_error ("expected 'break'");
  break_statement* s = new break_statement;
  s->tok = t;
  return s;
}


continue_statement*
parser::parse_continue_statement ()
{
  const token* t = next ();
  if (! (t->type == tok_keyword && t->content == "continue"))
    throw parse_error ("expected 'continue'");
  continue_statement* s = new continue_statement;
  s->tok = t;
  return s;
}


for_loop*
parser::parse_for_loop ()
{
  const token* t = next ();
  if (! (t->type == tok_keyword && t->content == "for"))
    throw parse_error ("expected 'for'");
  for_loop* s = new for_loop;
  s->tok = t;

  t = next ();
  if (! (t->type == tok_operator && t->content == "("))
    throw parse_error ("expected '('");

  // initializer + ";"
  t = peek ();
  if (t && t->type == tok_operator && t->content == ";")
    {
      s->init = 0;
      next ();
    }
  else
    {
      s->init = parse_expr_statement ();
      t = next ();
      if (! (t->type == tok_operator && t->content == ";"))
	throw parse_error ("expected ';'");
    }

  // condition + ";"
  t = peek ();
  if (t && t->type == tok_operator && t->content == ";")
    {
      literal_number* l = new literal_number(1);
      s->cond = l;
      s->cond->tok = next ();
    }
  else
    {
      s->cond = parse_expression ();
      t = next ();
      if (! (t->type == tok_operator && t->content == ";"))
	throw parse_error ("expected ';'");
    }
  
  // increment + ")"
  t = peek ();
  if (t && t->type == tok_operator && t->content == ")")
    {
      s->incr = 0;
      next ();
    }
  else
    {
      s->incr = parse_expr_statement ();
      t = next ();
      if (! (t->type == tok_operator && t->content == ")"))
	throw parse_error ("expected ')'");
    }

  // block
  s->block = parse_statement ();

  return s;
}


for_loop*
parser::parse_while_loop ()
{
  const token* t = next ();
  if (! (t->type == tok_keyword && t->content == "while"))
    throw parse_error ("expected 'while'");
  for_loop* s = new for_loop;
  s->tok = t;

  t = next ();
  if (! (t->type == tok_operator && t->content == "("))
    throw parse_error ("expected '('");

  // dummy init and incr fields
  s->init = 0;
  s->incr = 0;

  // condition
  s->cond = parse_expression ();

  t = next ();
  if (! (t->type == tok_operator && t->content == ")"))
    throw parse_error ("expected ')'");
  
  // block
  s->block = parse_statement ();

  return s;
}


foreach_loop*
parser::parse_foreach_loop ()
{
  const token* t = next ();
  if (! (t->type == tok_keyword && t->content == "foreach"))
    throw parse_error ("expected 'foreach'");
  foreach_loop* s = new foreach_loop;
  s->tok = t;
  s->sort_direction = 0;
  s->limit = NULL;

  t = next ();
  if (! (t->type == tok_operator && t->content == "("))
    throw parse_error ("expected '('");

  // see also parse_array_in

  bool parenthesized = false;
  t = peek ();
  if (t && t->type == tok_operator && t->content == "[")
    {
      next ();
      parenthesized = true;
    }

  while (1)
    {
      t = next ();
      if (! (t->type == tok_identifier))
        throw parse_error ("expected identifier");
      symbol* sym = new symbol;
      sym->tok = t;
      sym->name = t->content;
      s->indexes.push_back (sym);

      t = peek ();
      if (t && t->type == tok_operator &&
	  (t->content == "+" || t->content == "-"))
	{
	  if (s->sort_direction)
	    throw parse_error ("multiple sort directives");
	  s->sort_direction = (t->content == "+") ? 1 : -1;
	  s->sort_column = s->indexes.size();
	  next();
	}

      if (parenthesized)
        {
          t = peek ();
          if (t && t->type == tok_operator && t->content == ",")
            {
              next ();
              continue;
            }
          else if (t && t->type == tok_operator && t->content == "]")
            {
              next ();
              break;
            }
          else 
            throw parse_error ("expected ',' or ']'");
        }
      else
        break; // expecting only one expression
    }

  t = next ();
  if (! (t->type == tok_keyword && t->content == "in"))
    throw parse_error ("expected 'in'");
 
  s->base = parse_indexable();

  t = peek ();
  if (t && t->type == tok_operator &&
      (t->content == "+" || t->content == "-"))
    {
      if (s->sort_direction)
	throw parse_error ("multiple sort directives");
      s->sort_direction = (t->content == "+") ? 1 : -1;
      s->sort_column = 0;
      next();
    }

  t = peek ();
  if (tok_is(t, tok_keyword, "limit"))
    {
      next ();				// get past the "limit"
      s->limit = parse_expression ();
    }

  t = next ();
  if (! (t->type == tok_operator && t->content == ")"))
    throw parse_error ("expected ')'");

  s->block = parse_statement ();
  return s;
}


expression*
parser::parse_expression ()
{
  return parse_assignment ();
}


expression*
parser::parse_assignment ()
{
  expression* op1 = parse_ternary ();

  const token* t = peek ();
  // right-associative operators
  if (t && t->type == tok_operator 
      && (t->content == "=" ||
	  t->content == "<<<" ||
	  t->content == "+=" ||
	  t->content == "-=" ||
	  t->content == "*=" ||
	  t->content == "/=" ||
	  t->content == "%=" ||
	  t->content == "<<=" ||
	  t->content == ">>=" ||
	  t->content == "&=" ||
	  t->content == "^=" ||
	  t->content == "|=" ||
	  t->content == ".=" ||
	  false)) 
    {
      // NB: lvalueness is checked during elaboration / translation
      assignment* e = new assignment;
      e->left = op1;
      e->op = t->content;
      e->tok = t;
      next ();
      e->right = parse_expression ();

      t = peek ();
      if (t && t->type == tok_operator && t->content == "@@")
	{
	  do
	    { // consume consecutive @@ "foo bar" docstrings
	      next (); // swallow @@ itself
	      const token* t1 = next (); 
	      if (! (t1 && t1->type == tok_string))
		throw parse_error ("expected documentation string");
	      if (e->docstr != "") e->docstr += "\\n";
	      e->docstr += t1->content;
	      t = peek ();
	    } 
	  while (t && t->type == tok_operator && t->content == "@@");
	}
      
      op1 = e;
    }

  return op1;
}


expression*
parser::parse_ternary ()
{
  expression* op1 = parse_logical_or ();

  const token* t = peek ();
  if (t && t->type == tok_operator && t->content == "?")
    {
      ternary_expression* e = new ternary_expression;
      e->tok = t;
      e->cond = op1;
      next ();
      e->truevalue = parse_expression (); // XXX

      t = next ();
      if (! (t->type == tok_operator && t->content == ":"))
        throw parse_error ("expected ':'");

      e->falsevalue = parse_expression (); // XXX
      return e;
    }
  else
    return op1;
}


expression*
parser::parse_logical_or ()
{
  expression* op1 = parse_logical_and ();
  
  const token* t = peek ();
  while (t && t->type == tok_operator && t->content == "||")
    {
      logical_or_expr* e = new logical_or_expr;
      e->tok = t;
      e->op = t->content;
      e->left = op1;
      next ();
      e->right = parse_logical_and ();
      op1 = e;
      t = peek ();
    }

  return op1;
}


expression*
parser::parse_logical_and ()
{
  expression* op1 = parse_boolean_or ();

  const token* t = peek ();
  while (t && t->type == tok_operator && t->content == "&&")
    {
      logical_and_expr *e = new logical_and_expr;
      e->left = op1;
      e->op = t->content;
      e->tok = t;
      next ();
      e->right = parse_boolean_or ();
      op1 = e;
      t = peek ();
    }

  return op1;
}


expression*
parser::parse_boolean_or ()
{
  expression* op1 = parse_boolean_xor ();

  const token* t = peek ();
  while (t && t->type == tok_operator && t->content == "|")
    {
      binary_expression* e = new binary_expression;
      e->left = op1;
      e->op = t->content;
      e->tok = t;
      next ();
      e->right = parse_boolean_xor ();
      op1 = e;
      t = peek ();
    }

  return op1;
}


expression*
parser::parse_boolean_xor ()
{
  expression* op1 = parse_boolean_and ();

  const token* t = peek ();
  while (t && t->type == tok_operator && t->content == "^")
    {
      binary_expression* e = new binary_expression;
      e->left = op1;
      e->op = t->content;
      e->tok = t;
      next ();
      e->right = parse_boolean_and ();
      op1 = e;
      t = peek ();
    }

  return op1;
}


expression*
parser::parse_boolean_and ()
{
  expression* op1 = parse_array_in ();

  const token* t = peek ();
  while (t && t->type == tok_operator && t->content == "&")
    {
      binary_expression* e = new binary_expression;
      e->left = op1;
      e->op = t->content;
      e->tok = t;
      next ();
      e->right = parse_array_in ();
      op1 = e;
      t = peek ();
    }

  return op1;
}


expression*
parser::parse_array_in ()
{
  // This is a very tricky case.  All these are legit expressions:
  // "a in b"  "a+0 in b" "[a,b] in c" "[c,(d+0)] in b"
  vector<expression*> indexes;
  bool parenthesized = false;

  const token* t = peek ();
  if (t && t->type == tok_operator && t->content == "[")
    {
      next ();
      parenthesized = true;
    }

  while (1)
    {
      expression* op1 = parse_comparison ();
      indexes.push_back (op1);

      if (parenthesized)
        {
          const token* t = peek ();
          if (t && t->type == tok_operator && t->content == ",")
            {
              next ();
              continue;
            }
          else if (t && t->type == tok_operator && t->content == "]")
            {
              next ();
              break;
            }
          else 
            throw parse_error ("expected ',' or ']'");
        }
      else
        break; // expecting only one expression
    }

  t = peek ();
  if (t && t->type == tok_keyword && t->content == "in")
    {
      array_in *e = new array_in;
      e->tok = t;
      next (); // swallow "in"

      arrayindex* a = new arrayindex;
      a->indexes = indexes;
      a->base = parse_indexable();
      a->tok = a->base->get_tok();
      e->operand = a;
      return e;
    }
  else if (indexes.size() == 1) // no "in" - need one expression only
    return indexes[0];
  else
    throw parse_error ("unexpected comma-separated expression list");
}


expression*
parser::parse_comparison ()
{
  expression* op1 = parse_shift ();

  const token* t = peek ();
  while (t && t->type == tok_operator 
      && (t->content == ">" ||
          t->content == "<" ||
          t->content == "==" ||
          t->content == "!=" ||
          t->content == "<=" ||
          t->content == ">="))
    {
      comparison* e = new comparison;
      e->left = op1;
      e->op = t->content;
      e->tok = t;
      next ();
      e->right = parse_shift ();
      op1 = e;
      t = peek ();
    }

  return op1;
}


expression*
parser::parse_shift ()
{
  expression* op1 = parse_concatenation ();

  const token* t = peek ();
  while (t && t->type == tok_operator && 
         (t->content == "<<" || t->content == ">>"))
    {
      binary_expression* e = new binary_expression;
      e->left = op1;
      e->op = t->content;
      e->tok = t;
      next ();
      e->right = parse_concatenation ();
      op1 = e;
      t = peek ();
    }

  return op1;
}


expression*
parser::parse_concatenation ()
{
  expression* op1 = parse_additive ();

  const token* t = peek ();
  // XXX: the actual awk string-concatenation operator is *whitespace*.
  // I don't know how to easily to model that here.
  while (t && t->type == tok_operator && t->content == ".")
    {
      concatenation* e = new concatenation;
      e->left = op1;
      e->op = t->content;
      e->tok = t;
      next ();
      e->right = parse_additive ();
      op1 = e;
      t = peek ();
    }

  return op1;
}


expression*
parser::parse_additive ()
{
  expression* op1 = parse_multiplicative ();

  const token* t = peek ();
  while (t && t->type == tok_operator 
      && (t->content == "+" || t->content == "-"))
    {
      binary_expression* e = new binary_expression;
      e->op = t->content;
      e->left = op1;
      e->tok = t;
      next ();
      e->right = parse_multiplicative ();
      op1 = e;
      t = peek ();
    }

  return op1;
}


expression*
parser::parse_multiplicative ()
{
  expression* op1 = parse_unary ();

  const token* t = peek ();
  while (t && t->type == tok_operator 
      && (t->content == "*" || t->content == "/" || t->content == "%"))
    {
      binary_expression* e = new binary_expression;
      e->op = t->content;
      e->left = op1;
      e->tok = t;
      next ();
      e->right = parse_unary ();
      op1 = e;
      t = peek ();
    }

  return op1;
}


expression*
parser::parse_unary ()
{
  const token* t = peek ();
  if (t && t->type == tok_operator 
      && (t->content == "+" || 
          t->content == "-" || 
          t->content == "!" ||
          t->content == "~" ||
          false))
    {
      unary_expression* e = new unary_expression;
      e->op = t->content;
      e->tok = t;
      next ();
      e->operand = parse_crement ();
      return e;
    }
  else
    return parse_crement ();
}


expression*
parser::parse_crement () // as in "increment" / "decrement"
{
  // NB: Ideally, we'd parse only a symbol as an operand to the
  // *crement operators, instead of a general expression value.  We'd
  // need more complex lookahead code to tell apart the postfix cases.
  // So we just punt, and leave it to pass-3 to signal errors on
  // cases like "4++".

  const token* t = peek ();
  if (t && t->type == tok_operator 
      && (t->content == "++" || t->content == "--"))
    {
      pre_crement* e = new pre_crement;
      e->op = t->content;
      e->tok = t;
      next ();
      e->operand = parse_value ();
      return e;
    }

  // post-crement or non-crement
  expression *op1 = parse_value ();
  
  t = peek ();
  if (t && t->type == tok_operator 
      && (t->content == "++" || t->content == "--"))
    {
      post_crement* e = new post_crement;
      e->op = t->content;
      e->tok = t;
      next ();
      e->operand = op1;
      return e;
    }
  else
    return op1;
}


expression*
parser::parse_value ()
{
  const token* t = peek ();
  if (! t)
    throw parse_error ("expected value");

  if (t->type == tok_operator && t->content == "(")
    {
      next ();
      expression* e = parse_expression ();
      t = next ();
      if (! (t->type == tok_operator && t->content == ")"))
        throw parse_error ("expected ')'");
      return e;
    }
  else if (t->type == tok_identifier)
    return parse_symbol ();
  else
    return parse_literal ();
}


const token *
parser::parse_hist_op_or_bare_name (hist_op *&hop, string &name)
{
  hop = NULL;
  const token* t = expect_ident (name);
  if (name == "@hist_linear" || name == "@hist_log")
    {
      hop = new hist_op;
      if (name == "@hist_linear")
	hop->htype = hist_linear;
      else if (name == "@hist_log")
	hop->htype = hist_log;
      hop->tok = t;
      expect_op("(");
      hop->stat = parse_expression ();
      int64_t tnum;
      if (hop->htype == hist_linear)
	{
	  for (size_t i = 0; i < 3; ++i)
	    {
	      expect_op (",");
	      expect_number (tnum);
	      hop->params.push_back (tnum);
	    }
	}
      expect_op(")");
    }
  return t;
}


indexable*
parser::parse_indexable ()
{
  hist_op *hop = NULL;
  string name;
  const token *tok = parse_hist_op_or_bare_name(hop, name);
  if (hop)
    return hop;
  else
    {
      symbol* sym = new symbol;
      sym->name = name;
      sym->tok = tok;
      return sym;
    }
}


// var, indexable[index], func(parms), printf("...", ...), $var, $var->member, @stat_op(stat)
expression*
parser::parse_symbol () 
{
  hist_op *hop = NULL;
  symbol *sym = NULL;
  string name;
  const token *t = parse_hist_op_or_bare_name(hop, name);

  if (!hop)
    {
      // If we didn't get a hist_op, then we did get an identifier. We can 
      // now scrutinize this identifier for the various magic forms of identifier
      // (printf, @stat_op, and $var...)

      bool pf_stream, pf_format, pf_delim, pf_newline, pf_char;

      if (name.size() > 0 && name[0] == '@')
	{
	  stat_op *sop = new stat_op;
	  if (name == "@avg")
	    sop->ctype = sc_average;
	  else if (name == "@count")
	    sop->ctype = sc_count;
	  else if (name == "@sum")
	    sop->ctype = sc_sum;
	  else if (name == "@min")
	    sop->ctype = sc_min;
	  else if (name == "@max")
	    sop->ctype = sc_max;
	  else
	    throw parse_error("unknown statistic operator " + name);
	  expect_op("(");
	  sop->tok = t;
	  sop->stat = parse_expression ();
	  expect_op(")");
	  return sop;
	}
      
      else if (print_format::parse_print(name,
	 pf_stream, pf_format, pf_delim, pf_newline, pf_char))
	{
	  print_format *fmt = new print_format;
	  fmt->tok = t;
	  fmt->print_to_stream = pf_stream;
	  fmt->print_with_format = pf_format;
	  fmt->print_with_delim = pf_delim;
	  fmt->print_with_newline = pf_newline;
	  fmt->print_char = pf_char;

	  expect_op("(");
	  if ((name == "print" || name == "println") &&
	      (peek_kw("@hist_linear") || peek_kw("@hist_log")))
	    {
	      // We have a special case where we recognize
	      // print(@hist_foo(bar)) as a magic print-the-histogram
	      // construct. This is sort of gross but it avoids
	      // promoting histogram references to typeful
	      // expressions.
	      
	      hop = NULL;
	      t = parse_hist_op_or_bare_name(hop, name);
	      assert(hop);
	      
	      // It is, sadly, possible that even while parsing a
	      // hist_op, we *mis-guessed* and the user wishes to
	      // print(@hist_op(foo)[bucket]), a scalar. In that case
	      // we must parse the arrayindex and print an expression.
	      
	      if (!peek_op ("["))
		fmt->hist = hop;
	      else
		{
		  // This is simplified version of the
		  // multi-array-index parser below, because we can
		  // only ever have one index on a histogram anyways.
		  expect_op("[");
		  struct arrayindex* ai = new arrayindex;
		  ai->tok = t;
		  ai->base = hop;
		  ai->indexes.push_back (parse_expression ());
		  expect_op("]");
		  fmt->args.push_back(ai);
		}
	    }
	  else
	    {
	      int min_args = 0;
	      if (fmt->print_with_format)
		{
		  // Consume and convert a format string. Agreement between the
		  // format string and the arguments is postponed to the
		  // typechecking phase.
		  string tmp;
		  expect_unknown (tok_string, tmp);
		  fmt->raw_components = tmp;
		  fmt->components = print_format::string_to_components (tmp);
		}
	      else if (fmt->print_with_delim)
		{
		  // Consume a delimiter to separate arguments.
		  fmt->delimiter.clear();
		  fmt->delimiter.type = print_format::conv_literal;
		  expect_unknown (tok_string, fmt->delimiter.literal_string);
		  min_args = 2;
		}
	      else
		{
		  // If we are not printing with a format string, we must have
		  // at least one argument (of any type).
		  expression *e = parse_expression ();
		  fmt->args.push_back(e);
		}

	      // Consume any subsequent arguments.
	      while (min_args || !peek_op (")"))
		{
		  expect_op(",");
		  expression *e = parse_expression ();
		  fmt->args.push_back(e);
		  if (min_args)
		    --min_args;
		}
	    }
	  expect_op(")");
	  return fmt;
	}
      
      else if (name.size() > 0 && name[0] == '$')
	{
	  // target_symbol time
	  target_symbol *tsym = new target_symbol;
	  tsym->tok = t;
	  tsym->base_name = name;
	  while (true)
	    {
	      string c;
	      if (peek_op ("->"))
		{ 
		  next(); 
		  expect_ident_or_keyword (c);
		  tsym->components.push_back
		    (make_pair (target_symbol::comp_struct_member, c));
		}
	      else if (peek_op ("["))
		{ 
		  next();
		  expect_unknown (tok_number, c);
		  expect_op ("]");
		  tsym->components.push_back
		    (make_pair (target_symbol::comp_literal_array_index, c));
		}	    
	      else
		break;
	    }
	  return tsym;
	}

      else if (peek_op ("(")) // function call
	{
	  next ();
	  struct functioncall* f = new functioncall;
	  f->tok = t;
	  f->function = name;
	  // Allow empty actual parameter list
	  if (peek_op (")"))
	    {
	      next ();
	      return f;
	    }
	  while (1)
	    {
	      f->args.push_back (parse_expression ());
	      if (peek_op (")"))
		{
		  next();
		  break;
		}
	      else if (peek_op (","))
		{
		  next();
		  continue;
		}
	      else
		throw parse_error ("expected ',' or ')'");
	    }
	  return f;
	}

      else
	{
	  sym = new symbol;
	  sym->name = name;
	  sym->tok = t;
	}
    }
  
  // By now, either we had a hist_op in the first place, or else 
  // we had a plain word and it was converted to a symbol.

  assert (!hop != !sym); // logical XOR

  // All that remains is to check for array indexing

  if (peek_op ("[")) // array
    {
      next ();
      struct arrayindex* ai = new arrayindex;
      ai->tok = t;

      if (hop)
	ai->base = hop;
      else
	ai->base = sym;

      while (1)
        {
          ai->indexes.push_back (parse_expression ());
          if (peek_op ("]"))
            { 
	      next(); 
	      break; 
	    }
          else if (peek_op (","))
	    {
	      next();
	      continue;
	    }
          else
            throw parse_error ("expected ',' or ']'");
        }
      return ai;
    }

  // If we got to here, we *should* have a symbol; if we have
  // a hist_op on its own, it doesn't count as an expression,
  // so we throw a parse error.

  if (hop)
    throw parse_error("base histogram operator where expression expected", t);
  
  return sym;  
}

