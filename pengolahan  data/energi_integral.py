import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


# Fungsi untuk membaca data
def load_data(file_path):
    df = pd.read_csv(file_path, header=None, names=['time', 'power'], delimiter=',')
    df['time_sec'] = df['time'] / 1000  # Konversi waktu ke detik
    df['power_watt'] = df['power'] / 1000  # Konversi daya dari mW ke W
    return df

# Metode 1: Left Rectangle Rule
def left_rectangle_rule(df):
    delta_t = np.diff(df['time_sec'])  # Interval waktu antar data point
    energy = np.sum(df['power_watt'][:-1] * delta_t)  # Perkalian power dengan delta_t (kecuali poin terakhir)
    return energy

# Metode 2: Right Rectangle Rule
def right_rectangle_rule(df):
    delta_t = np.diff(df['time_sec'])
    energy = np.sum(df['power_watt'][1:] * delta_t)  # Perkalian power dengan delta_t (kecuali poin pertama)
    return energy

# Metode 3: Trapezoid Rule
def trapezoid_rule(df):
    energy = np.trapz(df['power_watt'], df['time_sec'])  # Menggunakan aturan trapezoidal
    return energy

# Main function untuk menjalankan semua metode dan menampilkan hasilnya
def main(file_path):
    # Baca data
    df = load_data(file_path)
    
    # Hitung energi menggunakan ketiga metode
    energy_left = left_rectangle_rule(df)
    energy_right = right_rectangle_rule(df)
    energy_trapezoid = trapezoid_rule(df)
    
    # Tampilkan hasil
    print("Total Energy (Left Rectangle Rule):", energy_left, "Joules")
    print("Total Energy (Right Rectangle Rule):", energy_right, "Joules")
    print("Total Energy (Trapezoid Rule):", energy_trapezoid, "Joules")
    
    # Grafik Daya vs Waktu
    plt.figure(figsize=(10, 6))
    plt.subplot(2, 1, 1)
    plt.plot(df['time_sec'], df['power_watt'], label='Power (W)', color='blue')
    plt.title('Power vs Time')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Power (W)')
    plt.grid(True)
    
    # Grafik Energi Kumulatif
    # Menghitung energi kumulatif berdasarkan waktu
    delta_t = np.diff(df['time_sec'])  # Selisih waktu antara titik data
    cumulative_energy_left = np.cumsum(df['power_watt'][:-1] * delta_t)
    cumulative_energy_right = np.cumsum(df['power_watt'][1:] * delta_t)
    
    # Untuk trapezoid, kita perlu menghitung kumulatif berdasarkan aturan trapezoid
    # Menghitung kumulatif energi trapezoid di setiap langkah
    cumulative_energy_trapezoid = np.zeros(len(df['time_sec']))
    for i in range(1, len(df['time_sec'])):
        cumulative_energy_trapezoid[i] = np.trapz(df['power_watt'][:i+1], df['time_sec'][:i+1])

    plt.subplot(2, 1, 2)
    plt.plot(df['time_sec'][1:], cumulative_energy_left, label='Left Rectangle Rule', color='red')
    plt.plot(df['time_sec'][1:], cumulative_energy_right, label='Right Rectangle Rule', color='green')
    plt.plot(df['time_sec'], cumulative_energy_trapezoid, label='Trapezoid Rule', color='orange')
    plt.title('Cumulative Energy vs Time')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Cumulative Energy (Joules)')
    plt.legend()
    plt.grid(True)
    
    # Menampilkan grafik
    plt.tight_layout()
    plt.show()

# Ganti path file dengan lokasi 'check_energy.csv'
main('check_energy.csv')