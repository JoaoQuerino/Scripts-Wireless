import matplotlib.pyplot as plt


def plot_reading_data(reading, reading_media, quantity_of_packages):
    """
    Plot reading data and related information.

    Parameters:
    reading (array-like): Array of reading values.
    reading_media (array-like): Mean reading values for each package.
    quantity_of_packages (array-like): Quantity of packages for each reading.

    Returns:
    None
    """
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