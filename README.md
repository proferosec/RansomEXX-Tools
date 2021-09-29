# RansomEXX Tools

This is a tool which can be used to extract the configuration values contained within a RansomEXX decryption tool which was provided by the attackers after an organization pays the ransom. The tool can also be used to decrypt a directory of encrypted files so that victims do not have to trust the binary given to them by the attacker.

**Note:** This is not a universal decryption tool, the ransom still needs to be paid to obtain the personalized decryption tool.

The full RansomEXX analysis that prompted the development of this tool can be found here: [https://medium.com/p/8e379bcaf701](https://medium.com/p/8e379bcaf701)

# Supported Versions

Currently the tool has only been tested on the ELF version of the X86\_64 decryption tool. It should be easy enough to add support for Windows and 32 bit binaries.

# Corrupted Files

Due to a bug in the encryption process in the RansomEXX malware some files encrypted by this malware could have been written to by a legitimate application during the encryption process, corrupting the file. If the nature of this corruption is simple, such as ASCII log file data being appended after the encrypted portion of the file, a file can be recovered.

During encryption the malware will append each file with RSA encrypted key information required to decrypt a file once a ransom is paid. When a file is being decrypted this information is read from the end of the file, decrypted with the RSA private key and then used to decrypt the file. For decryption to work in the case that legitimate data has been appended after the key information we need to truncate the file to remove this data, decrypt the file, and then append the data previously truncated.

# Decrypting with this tool

**Due to the potential of further damaging files corrupted by the malware when attempting to decrypt, do not carry out this operation on the only copy of the encrypted data.**.

When instructed to decrypt a directory this tool will traverse the directory tree and decrypt any files with the encrypted extension in place, removing the encrypted header added to the files by the malware and then rename the files to their original file names.

## Example

We have a directory containing encrypted files in `/home/user/encrypted-files` which we wish to decrypt and we have a RansomEXX decryption tool which was provided by the attackers and we do not wish to run at `/home/user/ransomexx-decryption-tool`. The steps required to decrypt these files with this tool are the following:

- Make a backup of these encrypted files in case of corrupted files being further damaged during decryption
- Extract the configuration information from the RansomEXX decryption tool
- Use this configuration to decrypt our files
- Sanity check the files to ensure none are corrupted and the decryption was carried out succesfully.

To extract the configuration into a file in `/home/user/config.json` run the following command:

```bash
./ransomexx-tools -exconfig -decryption-tool /home/user/ransomexx-decryption-tool -out /home/user/config.json
```

We can then use this configuration to decrypt our files with the following command:
```bash
./ransomexx-tools -decrypt -dirs /home/user/encrypted-files -config /home/user/config.json
```

## Usage

```
Usage of ./ransomexx-tools:
  -config string
    	Path of the extracted config file to use for decryption
  -debug
    	Log debug output
  -decrypt
    	Decrypt a list of directories
  -decryption-tool string
    	Path to the decryption tool to extract the config from. Required when using -exconfig
  -dirs string
    	A list of directories to recursively decrypt, separated by a comma
  -exconfig
    	Extract the config from a decryption tool provided by the RansomEXX group
  -num-workers int
    	Number of workers to use for decryption (default 4)
  -out string
    	The file to save the extracted config to
```

# Building

To build this tool ensure you have at least version 1.11 of Go installed so that you can build a Go modules.

Clone this repository and then build the tool with the following:
```bash
git clone https://github.com/proferosec/RansomEXX-Tools
cd RansomEXX-Tools
go build
```

# Decryption Process

RansomEXX uses symmetric encryption to partially encrypt files in AES CBC mode before encrypting the key and IV used with an RSA private key and appending them to the encrypted files.

The RansomEXX decryption tool contains the following information that this tool extracts into the json config file for decryption:

- RSA public modulus
- RSA public exponent
- RSA private exponent
- RSA first prime factor
- RSA second prime factor
- RSA DP value
- RSA DQ value
- RSA QP value
- The extension added to encrypted files
- The ransom note filename
- A list of potential "decrypt logic" values used to encrypt and decrypt the file

Most of these values are pretty straight forward and won't be documented here except for the list of potential "decrypt logic" values to use.

A "decrypt logic" is a set of values which determine how a file should be encrypted or decrypted in blocks. The decrypt logic to use for a file is determined by it's size in bytes. Each "decrypt logic" is a struct with the following C definition:

```c
struct DecryptLogic {
    uint64_t lowerLimit;
    uint64_t upperLimit;
    uint64_t chunkSize;
    uint64_t blockSize;
};
```

The `lowerLimit` value is the lower limit of files which should be encrypted/decrypted with the contained `chunkSize` and `blockSize` values while the `upperLimit` is the upper limit for the file size.

The `chunkSize` is the number of bytes which is read, encrypted/decrypted and then written back to an affected file at a time while the `blockSize` is the number of bytes to seek forward in the file after each chunk is encrypted/decrypted. As the `blockSize` in each decrypt logic, in the sample analyzed is larger than the corrosponding `chunkSize` this malware will only partially encrypt affected files but will encrypted enough to render the files unusable.

