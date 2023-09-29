# hash-breaker.go

A GoLang program to break hash codes. Utilizes concurrent workers to speed up the hash breaking process.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Go programming language installed

### Installation and Running

1. Download or clone this repository to your local machine.
2. Navigate to the directory of the file `main.go` in your terminal.
3. Run the program by entering the following command and replacing `<hex-hash>` with your hash:

```bash
go run main.go <hex-hash>
```

### Usage

```plaintext
Usage: hash_breaker <hex-hash>
```

#### Flags

- `-l <length>`: Length of the string to check (Default: 4)
- `-w <workers>`: Number of workers to use (Default: 8)
- `-log`: Enable logging (Default: false)
- `-e <encryption>`: Encryption algorithm to use (Default: sha256)
  - Valid options are: sha1, sha256, sha512, md5

Example usage:

```bash
go run main.go -l 5 -w 4 -log -e md5 <hex-hash>
```

## TODOs

- [ ] Add more flags to allow the user to specify the range of characters to check

## License

This project is open-source, feel free to use and modify it. A mention would be appreciated but is not required.

## Contributing

To contribute to this project, feel free to submit a pull request.

---

## Support

If you find any issues or have suggestions, please open an issue in the GitHub repository.
