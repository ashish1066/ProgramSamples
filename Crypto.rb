require "openssl"
require "base64"

include Base64

key = 'Bar12345Bar12345'
iv =  'RandomInitVector'

def encrypt(key,iv,plainText)
    cipher = OpenSSL::Cipher::AES128.new(:CBC)
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv
    cipher_text = cipher.update(plainText) + cipher.final
    encodedCipher = encode64(cipher_text)
return encodedCipher
end

def decrypt(key,iv,cipherText)
    decodeCipher = decode64(cipherText)
    cipher = OpenSSL::Cipher::AES128.new(:CBC)
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv
    decrypted_plain_text = cipher.update(decodeCipher) + cipher.final
return decrypted_plain_text
end


encryptedText = encrypt(key,iv,"Hello")
decryptedText = decrypt(key,iv,encryptedText)
puts "Encrypted Text : "+ encryptedText
puts "Decrypted Text : " + decryptedText

# puts "AES128 in CBC mode"
# puts "Key: " + urlsafe_encode64(key)
# puts "Iv: " + urlsafe_encode64(iv)
# puts "Plain text: " + plain_text
# puts "Cipher text: " + urlsafe_encode64(cipher_text)
# puts "Decrypted plain text: " + decrypted_plain_text
