import matplotlib.pyplot as plt


def plot_reading_data(reading, reading_media, quantity_of_packages):
    plt.figure(figsize=(12, 6))
    plt.plot(reading, reading_media, label='Media of package', 
             marker='o', color='grey')
    plt.bar(reading, quantity_of_packages, 
            label='Number of package read')

    plt.title('Number of readings per shift')
    plt.xlabel('per second(s)')
    plt.ylabel('quantity of packages')

    plt.legend()  # Adiciona a legenda com as etiquetas definidas acima
    plt.show()