import sys; from PIL import Image; img = Image.new('RGB', (1000, 1000), color = 'red'); img.save('test_large.jpg', quality=100)
