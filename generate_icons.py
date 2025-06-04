from PIL import Image, ImageDraw
import os

def create_icon(size, output_path):
    # Create a blue background
    bg_color = (74, 111, 165)  # Primary color from CSS
    img = Image.new('RGB', (size, size), bg_color)
    draw = ImageDraw.Draw(img)
    
    # Draw a simple lock icon
    padding = size // 4
    
    # Lock body (rectangle)
    body_top = size // 2
    draw.rectangle(
        [(padding, body_top), (size - padding, size - padding)],
        fill=(255, 255, 255)
    )
    
    # Lock shackle (simplified as rectangle)
    shackle_width = size // 3
    shackle_left = (size - shackle_width) // 2
    draw.rectangle(
        [(shackle_left, padding), (shackle_left + shackle_width, body_top)],
        outline=(255, 255, 255), width=size//20, fill=bg_color
    )
    
    # Add a keyhole
    keyhole_size = size // 10
    keyhole_x = size // 2
    keyhole_y = size - padding - keyhole_size
    draw.ellipse(
        [(keyhole_x - keyhole_size//2, keyhole_y - keyhole_size//2), 
         (keyhole_x + keyhole_size//2, keyhole_y + keyhole_size//2)],
        fill=bg_color
    )
    
    # Save the image
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    img.save(output_path)
    print(f"Created icon: {output_path}")

if __name__ == "__main__":
    # Create icons in different sizes
    create_icon(192, "static/icons/icon-192x192.png")
    create_icon(512, "static/icons/icon-512x512.png")
    print("Icon generation complete!") 