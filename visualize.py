import pandas as pd
import matplotlib.pyplot as plt

# Load the CSV file into a DataFrame
df = pd.read_csv('dmarc_report_analysis.csv')

# Plot the 'disposition' column
df['disposition'].value_counts().plot(kind='bar')
plt.title('DMARC Disposition Results')
plt.xlabel('Disposition')
plt.ylabel('Count')
plt.show()
