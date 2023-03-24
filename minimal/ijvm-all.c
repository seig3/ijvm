#include <stdlib.h> 	/* for malloc and atoi */
#include <stdio.h>      /* for FILE, fgetc, fputc, stdin, stdout, 
                         * fprintf, printf, fopen and fscanf */
#include <time.h>   	/* for time_t, time and ctime */

#include <string.h>
#include <ctype.h>

#include <malloc.h>

//#include <termios.h>
//#include <unistd.h>

#include "types.h"
#include "ijvm-all.h"
//#include "ijvm-util.h"
//#include "ijvm-spec.h"
//ijvm-spec.c

//ijvm-spec
IJVMSpec *
ijvm_spec_new ()
{
  IJVMSpec *spec;

  spec = malloc (sizeof (IJVMSpec));

  spec->templates = NULL;
  spec->ntemplates = 0;
  spec->allocation = 0;

  return spec;
}    

void
ijvm_spec_add_template (IJVMSpec *spec, IJVMInsnTemplate *tmpl)
{
  if (spec->ntemplates == spec->allocation) {
    spec->allocation = MAX (16, spec->allocation * 2);
    spec->templates = realloc (spec->templates, 
			       spec->allocation * sizeof (IJVMInsnTemplate *));
  }
  spec->templates[spec->ntemplates] = tmpl;
  spec->ntemplates++;
}

IJVMInsnTemplate *
ijvm_spec_lookup_template_by_mnemonic (IJVMSpec *spec, char *mnemonic)
{
  int i;

  for (i = 0; i < spec->ntemplates; i++)
    if (strcasecmp (mnemonic, spec->templates[i]->mnemonic) == 0)
      return spec->templates[i];
  return NULL;
}

IJVMInsnTemplate *
ijvm_spec_lookup_template_by_opcode (IJVMSpec *spec, int opcode)
{
  int i;

  for (i = 0; i < spec->ntemplates; i++)
    if (opcode == spec->templates[i]->opcode)
      return spec->templates[i];
  return NULL;
}

static struct { char *name; IJVMOperandKind kind; } operand_kinds[] =
{
  { "byte",        IJVM_OPERAND_BYTE },
  { "label",       IJVM_OPERAND_LABEL },
  { "method",      IJVM_OPERAND_METHOD },
  { "varnum",      IJVM_OPERAND_VARNUM },
  { "varnum-wide", IJVM_OPERAND_VARNUM_WIDE },
  { "constant",    IJVM_OPERAND_CONSTANT },
  { NULL, 0 }
};

static IJVMOperandKind
operand_name_to_kind (char *name)
{
  int i;

  for (i = 0; operand_kinds[i].name != NULL; i++)
    if (strcasecmp (name, operand_kinds[i].name) == 0)
      return operand_kinds[i].kind;

  fprintf (stderr, "Unknown operand type: `%s'\n", name);
  exit (-1);
  return 0;
}

static char *
operand_kind_to_name (IJVMOperandKind kind)
{
  return operand_kinds[kind].name;
}

static int line_number = 1;

/* Parse identifier from the string str, and strdup it into *id.
 * Return pointer to next non-whitespace char following the
 * identifier.
 */
static char *get_identifier (char *str, char **id)
{
  char *p;
  int len;

  p = str;
  while (isalnum ((int) *p) || *p == '-' || *p == '_')
    p++;
  if (p == str || !isalpha ((int) *str)) {
    fprintf (stderr, "Specification file parse error in line %d\n", 
	     line_number);
    exit (-1);
  }

  if (id != NULL) {
    len = p - str;
    *id = malloc (len + 1);
    strncpy (*id, str, len);
    (*id)[len] = 0;
  }

  while (*p && isspace ((int) *p))
    p++;

  return p;
}

/* Parse integer from the string str, and assign it to *i.  Return
 * pointer to next non-whitespace char following the integer.
 */
static char *get_int (char *str, int *i)
{
  char *p; 

  *i = strtol (str, &p, 0);
  if (p == str) {
    fprintf (stderr, "Specification file parse error in line %d\n", 
	     line_number);
    exit (-1);
  }

  while (*p && isspace ((int) *p))
    p++;

  return p;
}

static char *check_char (char *str, int c)
{
  char *p;

  if (*str == 0)
    return str;

  /* If we see a '#', then skip to end of line */
  if (*str == '#')
    return str + strlen (str);

  if (*str != c) {
    fprintf (stderr, "Specification file parse error in line %d\n", 
	     line_number);
    exit (-1);
  }

  p = str + 1;
  while (*p && isspace ((int) *p))
    p++;

  return p;
}

static int is_blank_line (char *str)
{
  int i;

  for (i = 0; str[i]; i++) {
    if (str[i] == '#')
      return 1;
    if (!isspace ((int) str[i]))
      return 0;
  }
  return 1;
}

IJVMInsnTemplate *
ijvm_insn_template_new (void)
{
  IJVMInsnTemplate *tmpl;

  tmpl = malloc (sizeof (IJVMInsnTemplate));

  tmpl->opcode = 0;
  tmpl->mnemonic = NULL;
  tmpl->operands = NULL;
  tmpl->noperands = 0;
  tmpl->nalloc = 0;

  return tmpl;  
}

void
ijvm_insn_template_add_operand (IJVMInsnTemplate *tmpl, IJVMOperandKind kind)
{
  if (tmpl->noperands == tmpl->nalloc) {
    tmpl->nalloc = MAX (4, tmpl->nalloc * 2);
    tmpl->operands = realloc (tmpl->operands, 
			      tmpl->nalloc * sizeof (IJVMOperandKind));
  }
  tmpl->operands[tmpl->noperands] = kind;
  tmpl->noperands++;
}

void
ijvm_spec_print (IJVMSpec *spec)
{
  int i, j;

  for (i = 0; i < spec->ntemplates; i++) {
    printf ("0x%2x %-13s ", 
	    spec->templates[i]->opcode, 
	    spec->templates[i]->mnemonic);
    for (j = 0; j < spec->templates[i]->noperands; j++)
      printf ("%s%s", j ? ", " : "", 
	      operand_kind_to_name (spec->templates[i]->operands[j]));
    printf ("\n");
  }
}

IJVMSpec *
ijvm_spec_parse (FILE *f)
{
  IJVMSpec *spec;
  IJVMInsnTemplate *tmpl;
  char buffer[MAX_LINESIZE], *p, *kind_name;
  IJVMOperandKind kind;

  spec = ijvm_spec_new ();
  while (fgets (buffer, MAX_LINESIZE, f)) {
    if (is_blank_line (buffer))
      continue;
    tmpl = ijvm_insn_template_new ();
    p = get_int (buffer, &tmpl->opcode);
    p = get_identifier (p, &tmpl->mnemonic);
    
    while (*p) {
      p = get_identifier (p, &kind_name);
      kind = operand_name_to_kind (kind_name);
      ijvm_insn_template_add_operand (tmpl, kind);
      p = check_char (p, ',');
    }
    ijvm_spec_add_template (spec, tmpl);
    line_number++;
  }

  return spec;
}

/* Search command line for `-f' option, then look in environment
 * variable IJVM_SPEC_FILE and eventually fall back on compiled in
 * default in order to determine name of spec file.  The parse the
 * file and return the specification.
 */

IJVMSpec *
ijvm_spec_init (int *argc, char *argv[])
{
  FILE *f;
  IJVMSpec *spec;
  char *spec_file;
  int i;

  spec_file = NULL;
  for (i = 1; i < *argc; i++) {
    if (strcmp (argv[i], "-f") == 0) {
      if (i + 1 < *argc) {
	spec_file = argv[i + 1];
	while (i + 2 < *argc) {
	  argv[i] = argv[i + 2];
	  i++;
	}
	*argc -= 2;
	argv[i] = NULL;
      }
      else {
	fprintf (stderr, "Option -f requires an argument\n");
	exit (-1);
      }
      break;
    }
  }

  if (spec_file == NULL) {
    //    if (getenv ("IJVM_SPEC_FILE") != NULL)
    //      spec_file = getenv ("IJVM_SPEC_FILE");
    //    else
      spec_file = "IJVMSPEC";
  }

  f = fopen (spec_file, "r");
  if (f == NULL) {
    fprintf (stderr, "Couldn't read specification file `%s'.\n", spec_file);
    exit (-1);
  }

  spec = ijvm_spec_parse (f);
  fclose (f);

  return spec;
}
//end of ijvm-spec

//ijvm-util
/* ijvm-util.c
 *
 * This file contains functions to disassemble and print IJVM
 * instructions as defined in the configuration file. */

static IJVMSpec *ijvm_spec;

/*
IJVMImage *ijvm_image_new (uint16 main_index, 
			   uint8 *method_area, uint16 method_area_size,
			   int32 *cpool, uint16 cpool_size)
{
  IJVMImage *image;

  image = malloc (sizeof (IJVMImage));
  image->main_index = main_index;
  image->method_area = malloc (method_area_size);
  memcpy (image->method_area, method_area, method_area_size);
  image->method_area_size = method_area_size;
  image->cpool = malloc (cpool_size * sizeof (int32));
  memcpy (image->cpool, cpool, cpool_size * sizeof (int32));
  image->cpool_size = cpool_size;

  return image;
}
*/
IJVMImage *
ijvm_image_load (FILE *file)
{
  IJVMImage *image;
  int j, fields;
  uint32 byte;
  uint16 method_area_size, cpool_size, main_index;
  int32 word;
  char temp;
  
  image = malloc (sizeof (IJVMImage));
  
  fields = fscanf (file, "main index: %d\n", &main_index);

  if (fields == 0) {
    printf ("Bytecode file not recognized\n");
    exit (-1);
  }
  image->main_index = main_index;
    
  fields = fscanf (file, "method area: %d bytes\n", &method_area_size);

  if (fields == 0) {
    printf ("Bytecode file not recognized\n");
    exit (-1);
  }

  image->method_area = malloc (method_area_size);

  image->method_area_size = method_area_size;
  for (j = 0; j < method_area_size-1; j++) {
    fscanf (file, "%x", &byte);
    image->method_area[j] = byte;
  }

  fscanf (file, "%x\n", &byte);
  image->method_area[method_area_size-1] = byte;

  fscanf (file, "%c", &temp);
  fscanf (file, "%c", &temp);

  fields = fscanf (file, "constant pool: %d words\n", &cpool_size);

  if (fields <= 0) {
    printf ("Bytecode file not recognized, cpool_size\n");
    exit (-1);
  }

  image->cpool = malloc (cpool_size * sizeof(int32));

  image->cpool_size = cpool_size;
  for (j = 0; j < cpool_size; j++) {
    fscanf (file, "%x", &word);
    image->cpool[j] = word;
  }

  return image;
}

void
ijvm_image_write (FILE *file, IJVMImage *image)
{
  int i;

  fprintf (file, "main index: %d\n", image->main_index);
  fprintf (file, "method area: %d bytes\n", image->method_area_size);
  for (i = 0; i < image->method_area_size; i++) {
    fprintf (file, "%02x", image->method_area[i] & 255);
    if ((i & 15) == 15 && i < image->method_area_size - 1)
      fprintf (file, "\n");
    else
      fprintf (file, " ");
  }
  if ((i & 15) != 0)
    fprintf (file, "\n");
  fprintf (file, "constant pool: %d words\n", image->cpool_size);
  for (i = 0; i < image->cpool_size; i++)
    fprintf (file, "%08x\n", image->cpool[i]);
}

static void
fill (int length)
{
  int j;

  for (j = 0; j < length; j++)
    printf (" ");
}

/* Setup the terminal to use charater based I/O.  Pretty much derived
 * from an example in the GNU Lib C info pages.  Type:
 *
 *   info libc "low-level term"
 *
 * at the prompt to view them.  We silently ignore errors; either
 * stdin is redirected from a file and thus not a tty, which is ok,
 * or something else is wrong, which we just dont care about.
 */
/*
static struct termios saved_term_attributes;

static void
reset_terminal (void)
{
  tcsetattr (STDIN_FILENO, TCSANOW, &saved_term_attributes);
}

void
ijvm_print_setup_terminal (void)
{
  struct termios attr;

  if (!isatty (STDIN_FILENO))
    return;
  tcgetattr (STDIN_FILENO, &saved_term_attributes);
  atexit (reset_terminal);

  tcgetattr (STDIN_FILENO, &attr);
  attr.c_lflag &= ~(ICANON | ECHO);
  attr.c_cc[VMIN] = 1;
  attr.c_cc[VTIME] = 0;
  tcsetattr (STDIN_FILENO, TCSAFLUSH, &attr);
}
*/
void
ijvm_print_init (int *argc, char *argv[])
{
  ijvm_spec = ijvm_spec_init (argc, argv);
  //  ijvm_print_setup_terminal ();
}

int
ijvm_get_opcode (char *mnemonic)
{
  IJVMInsnTemplate *tmpl;

  tmpl = ijvm_spec_lookup_template_by_mnemonic (ijvm_spec, mnemonic);
  if (tmpl == NULL)
    return -1;
  else
    return tmpl->opcode;
}

void
ijvm_print_stack (int32 *stack, int length, int indent)
{
  int i, *sp;

  if (indent)
    fill (32);

  printf ("stack = ");
  for (i = 0, sp = stack; i < length; i++, sp--)
    if (i == length - 1)
      printf ("%d", *sp);
    else
      printf ("%d, ", *sp);
  printf ("\n");
}

void
ijvm_print_opcodes (uint8 *opcodes, int length)
{
  int i;

  printf ("[");
  for (i = 0; i < length; i++)
    if (i == length - 1)
      printf ("%02x]  ", opcodes[i]);
    else
      printf ("%02x ", opcodes[i]);
  fill ((3 - length) * 3);
}

void
ijvm_print_snapshot (uint8 *opcodes)
{
  IJVMInsnTemplate *tmpl;
  uint8 opcode, byte;
  int8 sbyte;
  uint16 varnum, uword;
  int16 word;
  int j, length, index;


  opcode = opcodes[0];
  tmpl = ijvm_spec_lookup_template_by_opcode (ijvm_spec, opcode);
  if (tmpl == NULL) {
    printf ("unknown opcode: 0x%02x\n", opcode); 
    return;
  }

  length = printf ("%s ", tmpl->mnemonic);
  index = 1;

  for (j = 0; j < tmpl->noperands; j++) {
    if (j > 0)
      length += printf (", ");
    
    switch (tmpl->operands[j]) {
    case IJVM_OPERAND_BYTE:
      sbyte = opcodes[index];
      length += printf ("%d", sbyte);
      index += 1;
      break;

    case IJVM_OPERAND_LABEL:
      word = opcodes[index] * 256 + opcodes[index + 1];
      length += printf ("%d", word);
      index += 2;
      break;

    case IJVM_OPERAND_METHOD:
    case IJVM_OPERAND_CONSTANT:
      uword = opcodes[index] * 256 + opcodes[index + 1];
      length += printf ("%d", uword);
      index += 2;
      break;

    case IJVM_OPERAND_VARNUM:
      byte = opcodes[index];
      length += printf ("%d", byte);
      index += 1;
      break;

    case IJVM_OPERAND_VARNUM_WIDE:
      if (0) { /*FIXME*/
	varnum = opcodes[index] * 256 + opcodes[index + 1];
	length += printf ("%d", varnum);
	index += 2;
      }
      else {
	varnum = opcodes[index];
	length += printf ("%d", varnum);
	index += 1;
      }
      break;
    }
  }

  fill (20 - length);
  ijvm_print_opcodes (opcodes, index);
}


//end of ijvm-util

//ijvm.c
typedef struct _IJVM 
{
  uint16 sp, lv, pc, wide;
  int32 *stack;
  int32 *cpp;
  uint8 *method;

  uint16 initial_sp;
}IJVM;

int8   ijvm_fetch_int8 (IJVM *i);
uint8  ijvm_fetch_uint8 (IJVM *i);
int16  ijvm_fetch_int16 (IJVM *i);
uint16 ijvm_fetch_uint16 (IJVM *i);
void   ijvm_push (IJVM *i, int32 word);
int32  ijvm_pop (IJVM *i);
void   ijvm_invoke_virtual (IJVM *i, uint16 index);
void   ijvm_ireturn (IJVM *i);
void   ijvm_execute_opcode (IJVM *i);
int    ijvm_active (IJVM *i);
IJVM  *ijvm_new (IJVMImage *image, int argc, char *argv[]);

int8
ijvm_fetch_int8 (IJVM *i)
{
  int8 byte;

  byte = i->method[i->pc];
  i->pc = i->pc + 1;
  return byte;
}

uint8
ijvm_fetch_uint8 (IJVM *i)
{
  uint8 byte;

  byte = i->method[i->pc];
  i->pc = i->pc + 1;
  return byte;
}

int16
ijvm_fetch_int16 (IJVM *i)
{
  int16 word;

  word = i->method[i->pc] * 256 + i->method[i->pc + 1];
  i->pc = i->pc + 2;
  return word;
}

uint16
ijvm_fetch_uint16 (IJVM *i)
{
  uint16 word;

  word = i->method[i->pc] * 256 + i->method[i->pc + 1];
  i->pc = i->pc + 2;
  return word;
}

void
ijvm_push (IJVM *i, int32 word)
{
  i->sp = i->sp + 1;
  i->stack[i->sp] = word;
}

int32
ijvm_pop (IJVM *i)
{
  int32 result;

  result = i->stack[i->sp];
  i->sp = i->sp - 1;

  return result;
}

void ijvm_invoke_builtin (IJVM *i, uint16 index)
{
  int c;

  switch (index) {
  case 0:
    ijvm_pop (i);  /* Remove object ref. from stack. */
    c = fgetc (stdin);
    if (c == EOF)
      ijvm_push (i, -1); /* Return -1 as end of file */
    else
      ijvm_push (i, c);  /* Place return value on stack */
    break;
  case 1:
    c = fputc (ijvm_pop (i), stdout);
    ijvm_pop (i);  /* Remove object ref. from stack. */
    ijvm_push (i, c);  /* Place return value on stack */
  }
}

void
ijvm_invoke_virtual (IJVM *i, uint16 index)
{
  uint16 address=0;
  uint16 nargs=0, nlocals=0;

  if (index >= 0x8000) {
    ijvm_invoke_builtin (i, index - 0x8000);
    return;
  }

  address = i->cpp[index];
  nargs = i->method[address] * 256 + i->method[address + 1];
  nlocals  = i->method[address + 2] * 256 + i->method[address + 3];

  i->sp += nlocals;
  ijvm_push (i, i->pc);
  ijvm_push (i, i->lv);
  i->lv = i->sp - nargs - nlocals - 1;
  i->stack[i->lv] = i->sp - 1;
  i->pc = address + 4;

}

void
ijvm_ireturn (IJVM *i)
{
  int linkptr;

  linkptr = i->stack[i->lv];
  i->stack[i->lv] = i->stack[i->sp]; /* Leave result on top of stack */
  i->sp = i->lv;
  i->pc = i->stack[linkptr];
  i->lv = i->stack[linkptr + 1];
}

void
ijvm_execute_opcode (IJVM *i)
{
  uint8 opcode;
  uint16 index, varnum;
  int16 offset;
  int32 a, b;
  uint32 opc;

  opc = i->pc;
  opcode = ijvm_fetch_uint8 (i);

  switch (opcode) {
  case IJVM_OPCODE_BIPUSH:
    /* The next byte is fetched as a signed 8 bit value and then
     * sign extended to 32 bits */
    ijvm_push (i, ijvm_fetch_int8 (i));
    break;

  case IJVM_OPCODE_DUP:
    ijvm_push (i, i->stack[i->sp]);
    break;

  case IJVM_OPCODE_GOTO:
    /* Fetch the next 2 bytes interpreted as a signed 16 bit offset
     * and add this to pc. */
    offset = ijvm_fetch_int16 (i); 
    i->pc = opc + offset;
    break;

  case IJVM_OPCODE_IADD:
    a = ijvm_pop (i);
    b = ijvm_pop (i);
    ijvm_push (i, a + b);
    break;

  case IJVM_OPCODE_IAND:
    a = ijvm_pop (i);
    b = ijvm_pop (i);
    ijvm_push (i, a & b);
    break;

  case IJVM_OPCODE_IFEQ:
    offset = ijvm_fetch_int16 (i);
    a = ijvm_pop (i);
    if (a == 0)
      i->pc = opc + offset;
    break;

  case IJVM_OPCODE_IFLT:
    offset = ijvm_fetch_int16 (i);
    a = ijvm_pop (i);
    if (a < 0)
      i->pc = opc + offset;
    break;

  case IJVM_OPCODE_IF_ICMPEQ:
    offset = ijvm_fetch_int16 (i);
    a = ijvm_pop (i);
    b = ijvm_pop (i);
    if (a == b)
      i->pc = opc + offset;
    break;

  case IJVM_OPCODE_IINC:
    varnum = ijvm_fetch_uint8 (i);
    a = ijvm_fetch_int8 (i);
    i->stack[i->lv + varnum] += a;
    break;

  case IJVM_OPCODE_ILOAD:
    if (i->wide)
      varnum = ijvm_fetch_uint16 (i);
    else
      varnum = ijvm_fetch_uint8 (i);
    ijvm_push (i, i->stack[i->lv + varnum]);
    break;

  case IJVM_OPCODE_INVOKEVIRTUAL:
    index = ijvm_fetch_uint16 (i);
    ijvm_invoke_virtual (i, index);
    break; 
    
  case IJVM_OPCODE_IOR:
    a = ijvm_pop (i);
    b = ijvm_pop (i);
    ijvm_push (i, a | b);
    break;
    
  case IJVM_OPCODE_IRETURN:
    ijvm_ireturn (i);
    break; 

  case IJVM_OPCODE_ISTORE:
    if (i->wide)
      varnum = ijvm_fetch_uint16 (i);
    else
      varnum = ijvm_fetch_uint8 (i);
    i->stack[i->lv + varnum] = ijvm_pop (i);
    break;

  case IJVM_OPCODE_ISUB:
    a = ijvm_pop (i);
    b = ijvm_pop (i);
    ijvm_push (i, b - a);
    break;

  case IJVM_OPCODE_LDC_W:
    index = ijvm_fetch_uint16 (i);
    ijvm_push (i, i->cpp[index]);
    break;

  case IJVM_OPCODE_NOP:
    break;

  case IJVM_OPCODE_POP:
    ijvm_pop (i);
    break;

  case IJVM_OPCODE_SWAP:
    a = i->stack[i->sp];
    i->stack[i->sp] = i->stack[i->sp - 1];
    i->stack[i->sp - 1] = a;
    break;

  case IJVM_OPCODE_WIDE:
    i->wide = TRUE;
    break;
  }
  
  if (opcode != IJVM_OPCODE_WIDE)
    i->wide = FALSE;
}

/* The IJVM is active as long as PC is different from INITIAL_PC. PC
 * only becomes INITIAL_PC when an `ireturn' from (the initial
 * invocation of) main is executed, and this terminates the
 * interpreter. */

int
ijvm_active (IJVM *i)
{
  return i->pc != IJVM_INITIAL_PC;
}

void
ijvm_print_result (IJVM *i)
{
  printf ("return value: %d\n", i->stack[i->sp]);
}

/* Initialize a new IJVM interpreter given a bytecode image.  The
 * entry point for the java bytecode program is the method main.  The
 * index in the constant pool of the address of main is specified in
 * the bytecode file in the first line; eg. `main index: 38'.  The
 * arguments given on the command line are converted to integers and
 * passed to main. */

IJVM *
ijvm_new (IJVMImage *image, int argc, char *argv[])
{
  IJVM *i;
  int main_offset, nargs, j;
  char *end_ptr;
  
  i = malloc (sizeof (IJVM));

  i->sp = 0;
  i->lv = 0;
  i->pc = 0;
  i->wide = 0;
  i->initial_sp = 0;

  i->method = (uint8 *)malloc (IJVM_MEMORY_SIZE);
  memset (i->method, 0, IJVM_MEMORY_SIZE);

  i->cpp = (int32 *) (&(i->method[image->method_area_size]));
  
  i->stack = (int32 *) i->method;
  
  i->sp = (uint16)i->cpp + image->cpool_size - (uint16)i->stack - 1;
  i->initial_sp = i->sp;
  i->lv = 0;
  i->pc = IJVM_INITIAL_PC;
  i->wide = FALSE;

  memcpy (i->method, image->method_area, image->method_area_size);
  memcpy (i->cpp, image->cpool, image->cpool_size * sizeof (int32));

  main_offset = i->cpp[image->main_index];

  /* Number of arguments to main */  
  nargs = i->method[main_offset] * 256 + i->method[main_offset + 1];

  /* Dont count argv[0], argv[1] or obj. ref. */
  if (argc - 2 != nargs - 1) {
    printf ("Incorrect number of arguments. argc=%d nargs=%d\n",argc,nargs);
    exit (-1);
  }

  ijvm_push (i, IJVM_INITIAL_OBJ_REF);
  for (j = 0; j < nargs - 1; j++) {
    ijvm_push (i, strtol (argv[j + 2], &end_ptr, 0));
    if (argv[j + 2] == end_ptr) {
      printf ("Invalid argument to main method: `%s'\n", argv[j + 2]);
      exit (-1);
    }
  }      

  /* Initialize the IJVM by simulating a call to main */
  ijvm_invoke_virtual (i, image->main_index);

  return i;
}

int 
main (int argc, char *argv[])
{
  FILE *file;
  IJVMImage *image;
  IJVM *i;
  int verbose;
  char *time_string;
  time_t t;

  ijvm_print_init (&argc, argv);

  if (argc < 2) {
    fprintf (stderr, "Usage: ijvm [OPTION] FILENAME [PARAMETERS ...]\n\n");
    fprintf (stderr, "Where OPTION is\n\n");
    fprintf (stderr, "  -s            Silent mode.  No snapshot is produced.\n");
    fprintf (stderr, "  -f SPEC-FILE  The IJVM specification file to use.\n\n");
    fprintf (stderr, "If you pass `-' as the filename the simulator will read the bytecode\nfile from stdin.\n\n");
    fprintf (stderr, "You must specify as many arguments as your main method requires, except\n");
    fprintf (stderr, "one; the simulator will pass the initial object reference for you.\n");
    exit (-1);
  }

  verbose = TRUE;
  if (strcmp (argv[1], "-s") == 0) {
    verbose = FALSE;
    argv = argv + 1;
    argc = argc - 1;
  }

  if (strcmp (argv[1], "-") == 0)
    file = stdin;
  else
    file = fopen (argv[1], "r");
  if (file == NULL) {
    printf ("Could not open bytecode file `%s'\n", argv[1]);
    exit (-1);
  }

  image = ijvm_image_load (file);
  fclose (file);
  i = ijvm_new (image, argc, argv);

  if (verbose) {
    t = time (NULL);
    time_string = ctime (&t);
    printf ("IJVM Trace of %s %s\n", argv[1], time_string);
  }

  /* This is the interpreter main loop.  It essentially excecutes
   * ijvm_execute_opcode until the program terminates (which is when
   * an ireturn from main is encountered).  In each step, the
   * instruction, its arguments and the top 8 elements on the stack
   * are printed. */

  if (verbose)
    ijvm_print_stack (i->stack + i->sp, MIN (i->sp - i->initial_sp, 8), TRUE);
  while (ijvm_active (i)) {
    if (verbose){
      ijvm_print_snapshot (i->method + i->pc);
    }
      ijvm_execute_opcode (i);
    if (verbose)
      ijvm_print_stack (i->stack + i->sp, MIN (i->sp - i->initial_sp, 8), FALSE);
  }

  ijvm_print_result (i);
  return 0;
}
