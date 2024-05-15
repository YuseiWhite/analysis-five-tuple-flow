import sys
sys.path.append('/home/ubuntu/.pyenv/versions/3.10.14/lib/python3.10/site-packages')
from PIL import Image
import numpy as np
from typing import List

def analyze_and_save(data_name: str, num_of_pixel: int, five_tuple_flow_list: List):
    # データの取得と処理
    packet_sizes = np.array([d['packet_size'] for d in five_tuple_flow_list])
    interarrival_times = np.array([d['interarrival_time'] for d in five_tuple_flow_list])
    protocols = np.array([d['transport_protocol'] for d in five_tuple_flow_list])
    directions = np.array([d['direction'] for d in five_tuple_flow_list])  # direction情報の取得

    # データの正規化（最大値を特定値に固定する）
    normalized_sizes = packet_sizes * 255 / 1514  # packet size最大値を2000で255に正規化
    normalized_times = interarrival_times * 255 / 1e9 # interarrival time最大値を2000000000で255に正規化
    normalized_times = np.where(normalized_times > 255, 255, normalized_times)

    # 画像のサイズ変更（256x256に設定）
    img_size = num_of_pixel  # 画像サイズを256x256に変更

    # 画像データの初期化
    image = Image.new('RGBA', (img_size, img_size))  # 透明度を考慮してRGBAモードに変更

    index = 0
    for i in range(img_size):
        for j in range(img_size):
            if index < len(five_tuple_flow_list):
                # 赤色の設定: TCPのとき255, UDPのとき0
                red = 0 if protocols[index] == 6 else 255  # TCPは赤255, UDPは赤0
                # 透明度の設定: directionが1なら100%, 0なら10%
                alpha = 255 if directions[index] == 1 else 25  # 透明度を100%または10%に設定
                # 色の設定
                color = (red, int(normalized_sizes[index]), int(normalized_times[index]), alpha)
                image.putpixel((i, j), color)
            index += 1

    # 画像の表示
    print("making the image!")
    image.save(f"imgs/{data_name}.PNG")
    image.show()
