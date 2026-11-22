"""Plot the four CSV files produced by avalanche_diffusion.cpp.

Run in the directory containing the CSV files:
    python plot_avalanche_diffusion.py
Requires: matplotlib, pandas, numpy.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


# Load the four experiment CSVs and validate their shared run IDs.
def load_data():
    runs = pd.read_csv('runs.csv')
    histogram = pd.read_csv('avalanche_histogram.csv')
    by_bit = pd.read_csv('avalanche_by_bit.csv')
    diffusion = pd.read_csv('diffusion.csv')
    return runs, histogram, by_bit, diffusion


# Create comparable avalanche histograms and per-input-bit mean plots for each message length.
def plot_avalanche(runs, histogram, by_bit, directory):
    for message_bytes, group in runs.groupby('message_bytes', sort=True):
        fig, axes = plt.subplots(2, 1, figsize=(12, 9), constrained_layout=True)
        for row in group.itertuples(index=False):
            hist = histogram[histogram.run_id == row.run_id]
            mean = by_bit[by_bit.run_id == row.run_id]
            axes[0].plot(hist.distance_bits, hist.trial_count, label=row.algorithm)
            axes[1].plot(mean.input_bit, mean.mean_percent_changed, label=row.algorithm)
        axes[0].axvline(128, color='black', linestyle='--', linewidth=1, label='128-bit reference')
        axes[0].set(xlabel='Changed output bits (Hamming distance)', ylabel='Number of trials',
                    title=f'Avalanche histogram — {message_bytes}-byte inputs')
        axes[0].set_xlim(0, 256)
        axes[0].legend()
        axes[1].axhline(50, color='black', linestyle='--', linewidth=1, label='50% reference')
        axes[1].set(xlabel='Input bit position (MSB-first)', ylabel='Mean output bits changed (%)',
                    title=f'Avalanche by input bit — {message_bytes}-byte inputs')
        axes[1].set_ylim(0, 100)
        axes[1].legend()
        fig.savefig(directory / f'avalanche_{message_bytes}bytes.png', dpi=180)
        plt.close(fig)


# Plot an input-by-output influence heatmap with a common 0–1 color scale.
def plot_diffusion(runs, diffusion, directory):
    for row in runs.itertuples(index=False):
        subset = diffusion[diffusion.run_id == row.run_id]
        matrix = subset.pivot(index='input_bit', columns='output_bit', values='change_rate')
        fig, ax = plt.subplots(figsize=(13, 6), constrained_layout=True)
        image = ax.imshow(matrix.to_numpy(), aspect='auto', origin='upper',
                          vmin=0, vmax=1, cmap='coolwarm')
        if row.algorithm == 'Cayley hash':
            for boundary in (64, 128, 192):
                ax.axvline(boundary - 0.5, color='black', linestyle='--', linewidth=0.8)
        ax.set(xlabel='Output bit position (MSB-first)',
               ylabel='Input bit position (MSB-first)',
               title=f'Diffusion — {row.algorithm}, {row.message_bytes}-byte inputs, seed {row.seed}')
        fig.colorbar(image, ax=ax, label='Output bit change rate (0–1)', ticks=[0, .25, .5, .75, 1])
        fig.savefig(directory / f'diffusion_{row.run_id}.png', dpi=180)
        plt.close(fig)


# Load results and write the required plots to a separate figures directory.
def main():
    runs, histogram, by_bit, diffusion = load_data()
    directory = Path('figures')
    directory.mkdir(exist_ok=True)
    plot_avalanche(runs, histogram, by_bit, directory)
    plot_diffusion(runs, diffusion, directory)
    print(f'Plots saved in {directory.resolve()}')


if __name__ == '__main__':
    main()