import math
import numpy as np
from collections import Counter
import scipy.stats as stats
import matplotlib.pyplot as plt
import re

class RandomnessAnalyzer:
    @staticmethod
    def shannon_entropy(data):
        """Calculate Shannon entropy with detailed analysis."""
        if not data:
            return {'entropy': 0, 'max_possible_entropy': 8, 'randomness_percentage': 0}
        
        counter = Counter(data)
        total_count = len(data)
        max_entropy = math.log2(256)
        
        entropy = 0
        for count in counter.values():
            probability = count / total_count
            entropy -= probability * math.log2(probability)
        
        return {
            'entropy': entropy,
            'max_possible_entropy': max_entropy,
            'randomness_percentage': (entropy / max_entropy) * 100
        }

    @staticmethod
    def chi_square_test(data):
        """Perform chi-square test for uniform distribution."""
        counter = Counter(data)
        observed = [counter.get(i, 0) for i in range(256)]
        expected = len(data) / 256
        
        chi2, p_value = stats.chisquare(observed)
        return {
            'chi2_statistic': chi2,
            'p_value': p_value,
            'passes_test': p_value >= 0.05,
            'interpretation': 'Uniform distribution' if p_value >= 0.05 else 'Non-uniform distribution'
        }

    def analyze_randomness(self, data):
        """Comprehensive randomness analysis focusing on Shannon Entropy and Chi-Square test."""
        return {
            'shannon_entropy': self.shannon_entropy(data),
            'chi_square_test': self.chi_square_test(data)
        }

    def plot_byte_distribution(self, data, title='Byte Distribution'):
        """Visualize byte frequency distribution."""
        counter = Counter(data)
        plt.figure(figsize=(12, 6))
        plt.bar(counter.keys(), counter.values(), color='skyblue')
        plt.title(title)
        plt.xlabel('Byte Value')
        plt.ylabel('Frequency')
        plt.tight_layout()
        plt.show()

    @staticmethod
    def clean_hex_string(hex_string):
        """Clean and validate hex string."""
        # Remove any non-hexadecimal characters
        cleaned_hex = re.sub(r'[^0-9A-Fa-f]', '', hex_string)
        
        # Ensure length is even
        if len(cleaned_hex) % 2 != 0:
            cleaned_hex += '0'  # Add a '0' to make it even length
        
        return cleaned_hex

# Your specific data
ciphertext = [
    "559F8496A84B2D7C3F61FD7ECD445180A2B286BE43B416C6A2FEFFB0A0520B5",  # CHACHA20
    "AA5082B7F3D8BA61629F325952BFF7928F4F5B97276BE0C59D7A6ED2051E8B46F22B2C3659EA637C4EB397FE666", # AES
    "456F61717972706F6F6A286D6E6D3215657352D66C6D3F3C4E30E4AF27711F69E3", #Snow-V
    "4C62258E3D4BC7E079B72AAD80DFA0A20393A7FAD8932E7A7D51A5013999E54AA0B6415F6C5C842D98EDD81BE647C3A9" #clefia
]

# Initialize analyzers
analyzer = RandomnessAnalyzer()

# Loop through each ciphertext and analyze
for i, ciphertext_hex in enumerate(ciphertext):
    if ciphertext_hex:  # Only process non-empty strings
        try:
            # Clean and convert ciphertext to bytes
            cleaned_ciphertext = RandomnessAnalyzer.clean_hex_string(ciphertext_hex)
            ciphertext_bytes = bytes.fromhex(cleaned_ciphertext)

            # Analyze ciphertext
            print(f"Ciphertext {i+1} Randomness Analysis:")
            ciphertext_analysis = analyzer.analyze_randomness(ciphertext_bytes)
            for test, results in ciphertext_analysis.items():
                print(f"\n{test.replace('_', ' ').title()}:")
                for key, value in results.items():
                    print(f"  {key}: {value}")

            # Visualize distribution for this ciphertext
            analyzer.plot_byte_distribution(ciphertext_bytes, f"Ciphertext {i+1} Byte Distribution")

        except ValueError as e:
            print(f"Error converting ciphertext {i+1} to bytes: {e}")
    else:
        print(f"Ciphertext {i+1} is empty or invalid.")
