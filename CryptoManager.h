#ifndef CRYPTOMANAGER_H
#define CRYPTOMANAGER_H

#include <string>
#include <filesystem>

namespace fs = std::filesystem;

class CryptoManager {
public:
    // Удаляем конструктор копирования и оператор присваивания
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;

    // Статический метод для получения экземпляра
    static CryptoManager& getInstance();

    // Методы для работы с шифрованием
    void encryptFile(const fs::path& filePath);
    void decryptFile(const fs::path& filePath);
    void encryptDirectory(const fs::path& dirPath);
    void decryptDirectory(const fs::path& dirPath);

private:
    // Приватный конструктор
    CryptoManager() = default;

    // Вспомогательные методы
    std::string getPassword(const std::string& prompt = "Enter password: ");
    void generateKeyIV(const std::string& password, unsigned char* key, unsigned char* iv, unsigned char* salt);
    std::string encryptData(const std::string& data, const std::string& password, unsigned char* salt, unsigned char* iv);
    std::string decryptData(const std::string& ciphertext, const std::string& password, 
                          const unsigned char* salt, const unsigned char* iv);
};

#endif // CRYPTOMANAGER_H