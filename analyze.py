from PIL import Image
import numpy as np
from typing import List


def analyze_and_save(data_name: str, num_of_pixel: int, five_tuple_flow_list: List):
    packet_sizes = np.array([d['packet_size'] for d in five_tuple_flow_list])
    interarrival_times = np.array([d['interarrival_time'] for d in five_tuple_flow_list])
    protocols = np.array([d['transport_protocol'] for d in five_tuple_flow_list])
    directions = np.array([d['direction'] for d in five_tuple_flow_list])

    normalized_sizes = packet_sizes * 255 / 1514
    normalized_times = interarrival_times * 255 / 1e9
    normalized_times = np.where(normalized_times > 255, 255, normalized_times)

    img_size = num_of_pixel

    image = Image.new('RGBA', (img_size, img_size))

    index = 0
    for i in range(img_size):
        for j in range(img_size):
            if index < len(five_tuple_flow_list):
                # Red: UDP -> 255
                red = 0 if protocols[index] == 6 else 255
                # Transparency: in case of direction is 1 -> 100%, otherwise 10%
                alpha = 255 if directions[index] == 1 else 25
                color = (red, int(normalized_sizes[index]), int(normalized_times[index]), alpha)
                image.putpixel((i, j), color)
            index += 1

    print("making the image!")
    image.save(f"imgs/{data_name}.PNG")
    image.show()
