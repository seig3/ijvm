
#define MAX_LINESIZE 80
#define MAX(a, b) ((a) >= (b) ? (a) : (b))
//ijvm-util.h
//#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

//#define IJVM_MEMORY_SIZE (640 << 10) //0xA_0000
//#define IJVM_MEMORY_SIZE 128
#define IJVM_MEMORY_SIZE 256
#define IJVM_INITIAL_OBJ_REF 42
#define IJVM_INITIAL_PC 1

#define IJVM_OPCODE_BIPUSH        0x10
#define IJVM_OPCODE_DUP           0x59
#define IJVM_OPCODE_GOTO          0xA7
#define IJVM_OPCODE_IADD          0x60
#define IJVM_OPCODE_IAND          0x7E
#define IJVM_OPCODE_IFEQ    	  0x99
#define IJVM_OPCODE_IFLT    	  0x9B
#define IJVM_OPCODE_IF_ICMPEQ     0x9F
#define IJVM_OPCODE_IINC          0x84
#define IJVM_OPCODE_ILOAD         0x15
#define IJVM_OPCODE_INVOKEVIRTUAL 0xB6
#define IJVM_OPCODE_IOR           0x80
#define IJVM_OPCODE_IRETURN       0xAC
#define IJVM_OPCODE_ISTORE        0x36
#define IJVM_OPCODE_ISUB          0x64
#define IJVM_OPCODE_LDC_W         0x13
#define IJVM_OPCODE_NOP           0x00
#define IJVM_OPCODE_POP           0x57
#define IJVM_OPCODE_SWAP          0x5F
#define IJVM_OPCODE_WIDE          0xC4

typedef struct _IJVMImage {
  uint16 main_index;
  uint8 *method_area;
  uint32 method_area_size;
  int32 *cpool;
  uint32 cpool_size;
}IJVMImage;

typedef enum _IJVMOperandKind
{
  IJVM_OPERAND_BYTE,        /* 8 bit signed */
  IJVM_OPERAND_LABEL,       /* A label within current method */
  IJVM_OPERAND_METHOD,      /* The name of a method */
  IJVM_OPERAND_VARNUM,      /* 8 bit unsigned */
  IJVM_OPERAND_VARNUM_WIDE, /* 8 or 16 bit unsigned, emits wide */
  IJVM_OPERAND_CONSTANT     /* 32 bit signed, emits cpool index */
}IJVMOperandKind;

typedef struct _IJVMInsnTemplate
{
  int opcode;
  char *mnemonic;
  IJVMOperandKind *operands;  /* array of operand types this insn expects */
  int noperands, nalloc;      /* number of operands, allocated size of array */
}IJVMInsnTemplate;

typedef struct _IJVMSpec {
  IJVMInsnTemplate **templates;
  int ntemplates, allocation;
}IJVMSpec;

