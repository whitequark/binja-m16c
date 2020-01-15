from binaryninja import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType


__all__ = ['token', 'asm']


def token(kind, text, *data):
    if kind == 'opcode':
        tokenType = InstructionTextTokenType.OpcodeToken
    elif kind == 'opsep':
        tokenType = InstructionTextTokenType.OperandSeparatorToken
    elif kind == 'instr':
        tokenType = InstructionTextTokenType.InstructionToken
    elif kind == 'text':
        tokenType = InstructionTextTokenType.TextToken
    elif kind == 'reg':
        tokenType = InstructionTextTokenType.RegisterToken
    elif kind == 'int':
        tokenType = InstructionTextTokenType.IntegerToken
    elif kind == 'addr':
        tokenType = InstructionTextTokenType.PossibleAddressToken
    elif kind == 'codeRelAddr':
        tokenType = InstructionTextTokenType.CodeRelativeAddressToken
    elif kind == 'beginMem':
        tokenType = InstructionTextTokenType.BeginMemoryOperandToken
    elif kind == 'endMem':
        tokenType = InstructionTextTokenType.EndMemoryOperandToken
    else:
        raise ValueError('Invalid token kind {}'.format(kind))
    return InstructionTextToken(tokenType, text, *data)


def asm(*parts):
    tokens = []
    for part in parts:
        tokens.append(token(*part))
    return tokens
