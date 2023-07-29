from enum import Enum
from rich import print as r_print


class FontTypes(Enum):

    NORMAL = ['#FFFFFF']
    BOLD = ['bold', '#FFFFFF']
    ERROR = ['bold', '#FF0000']
    ALERT = ['bold', '#FFFF00']
    TESTE = ['bold', '#FF00FF']


def formater_text(str: str, font_type: FontTypes, word_indexes_to_format: list[int]) -> str:

    words = str.split()
    if isinstance(font_type.value, list):
        font_type = ' '.join(font_type.value)
    else:
        font_type = font_type.value

    for word_index in word_indexes_to_format:
        words[word_index] = f'[{font_type}]{words[word_index]}[/{font_type}]'

    return ' '.join(words)

def print(str: str):
    r_print(str)

x = 'texto a ser formatado'
print(formater_text(x, FontTypes.ERROR, [1, 2]))
print(formater_text(x, FontTypes.NORMAL, [1, 2]))
print(formater_text(x, FontTypes.ALERT, [1, 2]))
print(formater_text(x, FontTypes.BOLD, [1, 2]))
print(formater_text(x, FontTypes.TESTE, [1, 2]))



