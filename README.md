# Projeto de Cifragem e Decifragem de Arquivos Binários com AES-128

## 1. Descrição do projeto

Este projeto implementa manualmente um sistema de **cifragem e decifragem de arquivos binários** utilizando **AES-128** como cifra de bloco, sem uso de bibliotecas prontas de criptografia.

O programa foi desenvolvido em **C++** e permite:

- cifrar arquivos binários como `.jpg`, `.png`, `.pdf` e outros;
- aplicar **padding PKCS#7** manualmente para adequar o tamanho dos dados ao bloco de 16 bytes;
- decifrar o arquivo gerado e restaurar exatamente o conteúdo original;
- demonstrar, na prática, a confidencialidade e a integridade do processo de cifragem e decifragem.

O algoritmo utilizado foi o **AES-128 em modo CBC (Cipher Block Chaining)**.

---

## 2. Fundamentação teórica

### 2.1 O que é uma cifra de bloco

Uma cifra de bloco é um algoritmo criptográfico simétrico que opera sobre blocos fixos de dados. No caso do AES, cada bloco possui **128 bits**, ou seja, **16 bytes**. Isso significa que o arquivo a ser cifrado precisa ser dividido em blocos de 16 bytes para que o algoritmo consiga processá-lo.

Como arquivos binários podem ter qualquer tamanho, nem sempre a quantidade de bytes será múltipla de 16. Por isso, é necessário utilizar uma técnica de preenchimento chamada **padding**.

### 2.2 AES

O **AES (Advanced Encryption Standard)** é um padrão moderno de criptografia simétrica amplamente utilizado para proteção de dados. No AES-128:

- o tamanho do bloco é de 128 bits;
- a chave possui 128 bits;
- o algoritmo executa **10 rodadas** de transformação.

Cada rodada aplica operações matemáticas e substituições sobre os bytes do bloco, incluindo:

- **SubBytes**: substituição não linear de bytes usando a S-Box;
- **ShiftRows**: deslocamento circular das linhas do estado;
- **MixColumns**: mistura matemática das colunas no corpo finito GF(2^8);
- **AddRoundKey**: combinação do estado com a subchave da rodada.

No processo inverso, para a decifragem, são utilizadas as transformações contrárias:

- **InvSubBytes**
- **InvShiftRows**
- **InvMixColumns**
- **AddRoundKey**

### 2.3 Modo CBC

Neste trabalho foi utilizado o modo **CBC (Cipher Block Chaining)**. Nesse modo:

- antes de cifrar um bloco, ele é combinado com o bloco cifrado anterior por meio de XOR;
- para o primeiro bloco, utiliza-se um **vetor de inicialização (IV)**;
- isso evita que blocos iguais do arquivo original gerem blocos iguais no arquivo cifrado.

Matematicamente:

- **C1 = AES(P1 XOR IV)**
- **C2 = AES(P2 XOR C1)**
- e assim sucessivamente.

Na decifragem:

- **P1 = AES^-1(C1) XOR IV**
- **P2 = AES^-1(C2) XOR C1**

Esse encadeamento melhora a segurança em comparação ao modo ECB.

### 2.4 Padding PKCS#7

Como o AES exige blocos de 16 bytes, foi implementado manualmente o **PKCS#7**.

Funcionamento:

- calcula-se quantos bytes faltam para completar o último bloco;
- adicionam-se bytes extras com o mesmo valor dessa quantidade.

Exemplo:

Se faltarem 5 bytes para completar o bloco, são adicionados:

```text
05 05 05 05 05
```

Se o arquivo já tiver tamanho múltiplo de 16, um bloco inteiro de padding é adicionado com 16 bytes de valor `0x10`.

Na decifragem, o programa lê o último byte para saber quantos bytes devem ser removidos.

### 2.5 Processamento de arquivos binários

Diferentemente de mensagens de texto, arquivos binários devem ser lidos byte a byte sem qualquer interpretação de caracteres. Por isso, o programa utiliza leitura em modo binário para preservar exatamente o conteúdo do arquivo.

Esse cuidado é essencial para que uma imagem, PDF ou outro arquivo volte a abrir normalmente após a decifragem.

---

## 3. Estrutura do projeto

```text
aes_file_cipher_project/
├── main.cpp
├── CMakeLists.txt
├── .gitignore
└── README.md
```

---

## 4. Requisitos

- Compilador com suporte a **C++17**
- Linux, Windows ou macOS

---

## 5. Compilação

### 5.1 Compilação com g++

```bash
g++ -std=c++17 -O2 main.cpp -o aes_file_cipher
```

### 5.2 Compilação com CMake

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

---

## 6. Execução

### 6.1 Cifrar um arquivo

```bash
./aes_file_cipher encrypt imagem.jpg imagem.enc minhaChave123
```

### 6.2 Decifrar um arquivo

```bash
./aes_file_cipher decrypt imagem.enc imagem_restaurada.jpg minhaChave123
```

### 6.3 Estrutura do comando

```bash
./aes_file_cipher <encrypt|decrypt> <arquivo_entrada> <arquivo_saida> <chave>
```

---

## 7. Funcionamento do programa

### 7.1 Durante a cifragem

O programa:

1. lê o arquivo binário original;
2. gera a chave AES de 16 bytes a partir da chave informada pelo usuário;
3. gera um IV derivado da chave;
4. aplica padding PKCS#7;
5. divide os dados em blocos de 16 bytes;
6. cifra bloco a bloco usando AES-128 em modo CBC;
7. grava o IV seguido do conteúdo cifrado no arquivo de saída.

### 7.2 Durante a decifragem

O programa:

1. lê o arquivo cifrado;
2. extrai o IV dos primeiros 16 bytes;
3. decifra os blocos usando CBC;
4. remove o padding PKCS#7;
5. grava o arquivo restaurado no disco.

---

## 8. Como subir no GitHub

1. Crie um novo repositório no GitHub.
2. Envie os seguintes arquivos:
   - `main.cpp`
   - `README.md`
   - `CMakeLists.txt`
   - `.gitignore`
3. No terminal, você pode usar:

```bash
git init
git add .
git commit -m "Projeto AES-128 para cifragem e decifragem de arquivos binários"
git branch -M main
git remote add origin SEU_LINK_DO_REPOSITORIO
git push -u origin main
```

---

## 9. O que mostrar no vídeo de validação

O vídeo pode ter até 5 minutos e pode seguir este roteiro:

### Introdução
- apresentar o objetivo do trabalho;
- informar que foi implementado manualmente um algoritmo AES-128 para cifrar e decifrar arquivos binários.

### Demonstração do código
- mostrar o arquivo `main.cpp`;
- destacar:
  - implementação do AES;
  - funções de `SubBytes`, `ShiftRows`, `MixColumns` e expansão de chave;
  - modo CBC;
  - padding PKCS#7;
  - leitura e escrita binária de arquivos.

### Demonstração prática
- escolher uma imagem `.jpg` ou `.png`;
- executar a cifragem;
- mostrar que o arquivo cifrado não abre como imagem normal;
- executar a decifragem;
- abrir o arquivo restaurado e comprovar que ele voltou ao estado original.

### Encerramento
- reforçar que o sistema preserva o arquivo original após a decifragem;
- concluir que o objetivo da atividade foi cumprido.

---

## 10. Observações importantes

- O projeto foi desenvolvido com fins acadêmicos.
- A chave informada pelo usuário é convertida para 16 bytes, preenchendo com `0x00` caso seja menor.
- O arquivo cifrado armazena o IV nos 16 primeiros bytes para permitir a decifragem posterior.
- Como se trata de uma implementação didática, o foco principal está em demonstrar o funcionamento interno da cifra de bloco e do tratamento de arquivos binários.

---

## 11. Exemplo de teste

Supondo que exista uma imagem chamada `foto.jpg`:

### Cifrar

```bash
./aes_file_cipher encrypt foto.jpg foto.enc senha123
```

### Decifrar

```bash
./aes_file_cipher decrypt foto.enc foto_restaurada.jpg senha123
```

Ao final, o arquivo `foto_restaurada.jpg` deve abrir normalmente e possuir o mesmo conteúdo do arquivo original.

---

## 12. Conclusão

Este projeto atende aos requisitos da atividade ao implementar, sem bibliotecas prontas de criptografia, um sistema completo de cifragem e decifragem de arquivos binários baseado em cifra de bloco. A solução utiliza AES-128, padding PKCS#7 e modo CBC, permitindo processar arquivos reais e restaurá-los corretamente após a decifragem.
