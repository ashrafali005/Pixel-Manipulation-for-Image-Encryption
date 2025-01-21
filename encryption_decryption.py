import os
import requests
from PIL import Image
import numpy as np

def download_image(url, save_path):
    """Download an image from a URL to a local file."""
    try:
        print("Downloading image from URL...")
        response = requests.get(url, stream=True)
        response.raise_for_status()  # Raise HTTPError for bad responses
        with open(save_path, 'wb') as file:
            for chunk in response.iter_content(1024):
                file.write(chunk)
        print("Image downloaded successfully.")
        return save_path
    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to the internet. Check your connection.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error downloading image: {e}")
        return None

def encrypt_image(image_path, output_path, key):
    """Encrypt an image by XORing its pixel data with the key."""
    try:
        # Ensure the key is within the uint8 range
        key = key % 256

        # Check if output path is a directory
        if os.path.isdir(output_path):
            raise IsADirectoryError(f"The output path '{output_path}' is a directory, not a file.")

        # Open the image and convert to RGB
        print("Encrypting the image...")
        image = Image.open(image_path).convert('RGB')
        image_data = np.array(image)

        # XOR operation for encryption
        encrypted_data = image_data ^ key

        # Convert back to image and save
        encrypted_image = Image.fromarray(encrypted_data.astype('uint8'))
        encrypted_image.save(output_path)
        print("Image encrypted and saved to:", output_path)
    except Exception as e:
        print("Error encrypting the image:", e)

def decrypt_image(image_path, output_path, key):
    """Decrypt an image by XORing its pixel data with the key."""
    try:
        # Ensure the key is within the uint8 range
        key = key % 256

        # Check if output path is a directory
        if os.path.isdir(output_path):
            raise IsADirectoryError(f"The output path '{output_path}' is a directory, not a file.")

        # Open the image and convert to RGB
        print("Decrypting the image...")
        image = Image.open(image_path).convert('RGB')
        image_data = np.array(image)

        # XOR operation for decryption
        decrypted_data = image_data ^ key

        # Convert back to image and save
        decrypted_image = Image.fromarray(decrypted_data.astype('uint8'))
        decrypted_image.save(output_path)
        print("Image decrypted and saved to:", output_path)
    except Exception as e:
        print("Error decrypting the image:", e)

def main():
    """Main menu for image encryption and decryption."""
    print("=== Pixel Manipulation for Image Encryption ===")
    while True:
        print("\n1. Encrypt an Image")
        print("2. Decrypt an Image")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == "1":
            image_url = input("Enter the URL of the image to encrypt: ").strip()
            temp_path = "temp_image_to_encrypt.png"
            output_path = input("Enter the output path for the encrypted image (include filename): ").strip()
            try:
                key = int(input("Enter an encryption key (integer value): "))
            except ValueError:
                print("Error: Please enter a valid integer key.")
                continue

            if download_image(image_url, temp_path):
                encrypt_image(temp_path, output_path, key)
                os.remove(temp_path)  # Clean up temporary file
            else:
                print("Failed to process the URL.")

        elif choice == "2":
            image_path = input("Enter the path of the encrypted image: ").strip()
            output_path = input("Enter the output path for the decrypted image (include filename): ").strip()
            try:
                key = int(input("Enter the encryption key (integer value): "))
            except ValueError:
                print("Error: Please enter a valid integer key.")
                continue

            if os.path.exists(image_path):
                decrypt_image(image_path, output_path, key)
            else:
                print(f"Error: File '{image_path}' does not exist.")

        elif choice == "3":
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
