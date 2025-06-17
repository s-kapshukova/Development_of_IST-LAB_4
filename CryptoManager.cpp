#include "CryptoManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <termios.h>
#include <unistd.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>

using namespace CryptoPP;

const std::string ENCRYPTED_EXT = ".enc";
const std::string MAGIC_HEADER = "ENCv1";

// Получение единственного экземпляра
CryptoManager& CryptoManager::getInstance() {
    static CryptoManager instance;
    return instance;
}

// Метод для получения пароля
std::string CryptoManager::getPassword(const std::string& prompt) {
    std::cout << prompt;
    
    struct termios oldt, newt; 
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::string password;
    std::getline(std::cin, password);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
    
    return password;
}

// Генерация ключа и вектора инициализации
void CryptoManager::generateKeyIV(const std::string& password, 
                                unsigned char* key, 
                                unsigned char* iv, 
                                unsigned char* salt) {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(salt, 8);
    
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    byte unused = 0;
    pbkdf.DeriveKey(key, AES::DEFAULT_KEYLENGTH, unused,
                   (const byte*)password.data(), password.size(),
                   salt, 8, 100000);
    
    std::string iv_src = password + std::string((char*)salt, 8);
    SHA256().CalculateDigest(iv, (const byte*)iv_src.data(), iv_src.size());
}

// Шифрование данных
std::string CryptoManager::encryptData(const std::string& data, 
                                     const std::string& password, 
                                     unsigned char* salt, 
                                     unsigned char* iv) {
    byte key[AES::DEFAULT_KEYLENGTH];
    generateKeyIV(password, key, iv, salt);
    
    CBC_Mode<AES>::Encryption encryptor(key, sizeof(key), iv);
    std::string ciphertext;
    //Шифруем данные через AES-CBC
    StringSource(data, true,    //Данные -> шифрование/дешифрование -> результат
        new StreamTransformationFilter(encryptor,
            new StringSink(ciphertext)
        )
    );
    return ciphertext;
}

// Дешифрование данных
std::string CryptoManager::decryptData(const std::string& ciphertext, 
                                     const std::string& password, 
                                     const unsigned char* salt, 
                                     const unsigned char* iv) {
    byte key[AES::DEFAULT_KEYLENGTH];
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    byte unused = 0;
    pbkdf.DeriveKey(key, sizeof(key), unused,
                   (const byte*)password.data(), password.size(),
                   salt, 8, 100000);
    
    CBC_Mode<AES>::Decryption decryptor(key, sizeof(key), iv);
    std::string decrypted;
    StringSource(ciphertext, true,
        new StreamTransformationFilter(decryptor,
            new StringSink(decrypted)
        )
    );
    return decrypted;
}

// Шифрование файла
void CryptoManager::encryptFile(const fs::path& filePath) {
    std::string password = getPassword();
    std::string confirm = getPassword("Confirm password: ");
    if (password != confirm) {
        std::cerr << "Passwords don't match!\n";
        return;
    }

    std::ifstream in(filePath, std::ios::binary);
    std::string data((std::istreambuf_iterator<char>(in)), {});
    in.close();

    unsigned char salt[8], iv[AES::BLOCKSIZE];
    std::string ciphertext = encryptData(MAGIC_HEADER + data, password, salt, iv);

    fs::path outPath = filePath.string() + ENCRYPTED_EXT;
    std::ofstream out(outPath, std::ios::binary);
    out.write(reinterpret_cast<const char*>(salt), 8);
    out.write(reinterpret_cast<const char*>(iv), AES::BLOCKSIZE);
    out << ciphertext;
    out.close();

    fs::remove(filePath);
    std::cout << "File encrypted: " << outPath << "\n";
}

// Дешифрование файла
void CryptoManager::decryptFile(const fs::path& filePath) {
    if (!fs::exists(filePath) || filePath.extension() != ENCRYPTED_EXT) {
        std::cerr << "Not an encrypted file or file doesn't exist!\n";
        return;
    }

    std::string password = getPassword();
    
    std::ifstream in(filePath, std::ios::binary);
    unsigned char salt[8], iv[AES::BLOCKSIZE];
    in.read(reinterpret_cast<char*>(salt), 8);
    in.read(reinterpret_cast<char*>(iv), AES::BLOCKSIZE);
    std::string ciphertext((std::istreambuf_iterator<char>(in)), {});
    in.close();

    std::string decrypted = decryptData(ciphertext, password, salt, iv);
    if (decrypted.substr(0, MAGIC_HEADER.size()) != MAGIC_HEADER) {
        std::cerr << "Wrong password or corrupted file!\n";
        return;
    }
    decrypted = decrypted.substr(MAGIC_HEADER.size());

    fs::path outputPath = filePath;
    outputPath.replace_extension("");
    
    std::ofstream out(outputPath, std::ios::binary);
    out << decrypted;
    out.close();

    fs::remove(filePath);
    std::cout << "File decrypted to: " << outputPath << "\n";
}

// Шифрование директории
void CryptoManager::encryptDirectory(const fs::path& dirPath) {
    std::string password = getPassword();
    std::string confirm = getPassword("Confirm password: ");
    if (password != confirm) {
        std::cerr << "Passwords don't match!\n";
        return;
    }

    std::stringstream archive; //временное хранилище файлов
    //рекурсивный обход папки
    for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
        if (entry.is_regular_file()) {
            std::string path = fs::relative(entry.path(), dirPath).string();
            std::ifstream file(entry.path(), std::ios::binary);
            archive << path << "\n";
            archive << file.rdbuf() << "\n";
        }
    }

    unsigned char salt[8], iv[AES::BLOCKSIZE];
    std::string ciphertext = encryptData(MAGIC_HEADER + archive.str(), password, salt, iv);

    fs::path outPath = dirPath.string() + ENCRYPTED_EXT;
    std::ofstream out(outPath, std::ios::binary);
    out.write(reinterpret_cast<const char*>(salt), 8);
    out.write(reinterpret_cast<const char*>(iv), AES::BLOCKSIZE);
    out << ciphertext;
    out.close();

    fs::remove_all(dirPath);
    std::cout << "Directory encrypted: " << outPath << "\n";
}

// Дешифрование директории
void CryptoManager::decryptDirectory(const fs::path& dirPath) {
    if (!fs::exists(dirPath)) {
        std::cerr << "File not found!\n";
        return;
    }

    std::string password = getPassword();
    
    std::ifstream in(dirPath, std::ios::binary);
    unsigned char salt[8], iv[AES::BLOCKSIZE];
    in.read(reinterpret_cast<char*>(salt), 8);
    in.read(reinterpret_cast<char*>(iv), AES::BLOCKSIZE);
    std::string ciphertext((std::istreambuf_iterator<char>(in)), {});
    in.close();

    std::string decrypted = decryptData(ciphertext, password, salt, iv);
    if (decrypted.substr(0, MAGIC_HEADER.size()) != MAGIC_HEADER) {
        std::cerr << "Wrong password or corrupted file!\n";
        return;
    }
    decrypted = decrypted.substr(MAGIC_HEADER.size());

    fs::path outputPath = dirPath;
    outputPath.replace_extension("");

    if (decrypted.find('\n') != std::string::npos) {
        fs::create_directories(outputPath);
        std::istringstream iss(decrypted);
        std::string line;
        while (std::getline(iss, line)) {
            fs::path filePath = outputPath / line;
            fs::create_directories(filePath.parent_path());
            
            std::string content;
            std::getline(iss, content);
            
            std::ofstream file(filePath, std::ios::binary);
            file << content;
        }
        std::cout << "Directory decrypted to: " << outputPath << "\n";
    }
    fs::remove(dirPath);
}

int main() {
    // Получаем экземпляр менеджера
    CryptoManager& cryptoManager = CryptoManager::getInstance();

    std::cout << "1. Encrypt file\n2. Decrypt file\n3. Encrypt folder\n4. Decrypt folder\nChoice: ";
    int choice;
    std::cin >> choice;
    std::cin.ignore();

    std::string path;
    std::cout << "Enter path: ";
    std::getline(std::cin, path);

    try {
        switch (choice) {
            case 1: cryptoManager.encryptFile(path); break;
            case 2: cryptoManager.decryptFile(path); break;
            case 3: cryptoManager.encryptDirectory(path); break;
            case 4: cryptoManager.decryptDirectory(path); break;
            default: std::cerr << "Invalid choice!\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }

    return 0;
}