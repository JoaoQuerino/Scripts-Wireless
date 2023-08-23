from enum import Enum
from rich.console import Console


__console = Console()


class FontTypes(Enum):
    """
        #TODO Fazer as docstring do view
    """

    NORMAL = ['#FFFFFF']
    BOLD = ['bold', '#FFFFFF']
    ERROR = ['bold', '#F00000']
    ALERT = ['bold', '#FFFF00']
    TESTE = ['bold', '#FF00FF']


def formater_text(str: str, font_type: FontTypes, word_indexes_to_format: list[int]=-1) -> str:
    """
    Formats specific words or the entire text with a given font type.

    Args:
        text (str): The input text to be formatted.
        font_type (FontTypes): The font type to apply to the specified words or entire text.
        word_indexes_to_format (list[int], optional): List of word indexes to format.
            Default is -1, which means formatting the entire text.

    Returns:
        str: Formatted text.
    """

    if isinstance(font_type.value, list):
        font_type = ' '.join(font_type.value)
    else:
        font_type = font_type.value

    if word_indexes_to_format == -1:
        return f'[{font_type}]{str}[/{font_type}]'

    words = str.split()
    for word_index in word_indexes_to_format:
        words[word_index] = f'[{font_type}]{words[word_index]}[/{font_type}]'

    return ' '.join(words)


def f_print(str: str):
    __console.print(str)

def f_input(str: str) -> str:
    return __console.input(str)    