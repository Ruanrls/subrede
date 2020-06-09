# subrede
Divisão em subredes

How to use:

-f {path}               Coloque o caminho do arquivo que contém os ips para serem calculados
-o {path}              Coloque o caminho com o nome do arquivo onde será salvo o output
-v                      Deixa o script com a verbosidade ativa
-so -o {path}           Salva o output em 3 arquivos separados... Coloque apenas o caminho no path (-o) sem a barra no final


Exemplos de uso:

python script.py -f Desktop/ips.txt -o resolved.txt

python script.py -f Desktop/ips.txt -so -o Desktop/folder
