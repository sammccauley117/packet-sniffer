import pandas as pd
import numpy as np
import csv, os
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.svm import SVC
from sklearn.svm import LinearSVC
from sklearn import tree
from sklearn.metrics import f1_score
from sklearn.metrics import precision_score, recall_score

# Clean files
if os.path.exists("accuracy.csv"):  os.remove("accuracy.csv")
if os.path.exists("precision.csv"): os.remove("precision.csv")
if os.path.exists("recall.csv"):    os.remove("recall.csv")
if os.path.exists("f1.csv"):        os.remove("f1.csv")

# Load data
df = pd.read_csv("data.csv", header=None)
columns_list = ['packet_count', 'total_len', 'avg_len', 'proto', 'sr', 'ip_flag', 'tcp_flags', 'sport', 'dport', 'label']
df.columns = columns_list
features = ['packet_count', 'total_len', 'avg_len', 'proto', 'sr', 'ip_flag', 'tcp_flags', 'sport', 'dport']
X = df[features]
y = df['label']

# Initialize data containers
a = [] # Accuracy
p = [] # Precision
r = [] # Recall
f = [] # F1

# Train and test models
for i in range(0, 10):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25)

    # Decision Tree
    model1 = tree.DecisionTreeClassifier()
    model1.fit(X_train, y_train)

    # Neural network
    model2 = MLPClassifier()
    model2.fit(X_train, y_train)

    # SVM's
    model3 = SVC(gamma='auto') #SVC USE THIS
    model3.fit(X_train, y_train)

    # Get score results
    a1 = model1.score(X_test, y_test)
    a2 = model2.score(X_test, y_test)
    a3 = model3.score(X_test, y_test)
    a.append(','.join([str(a1), str(a2), str(a3)]) + '\n')

    # Get precisions
    y1 = model1.predict(X_test)
    y2 = model2.predict(X_test)
    y3 = model3.predict(X_test)
    p1 = precision_score(y_test, y1, average='micro')
    p2 = precision_score(y_test, y2, average='micro')
    p3 = precision_score(y_test, y3, average='micro')
    p.append(','.join([str(p1), str(p2), str(p3)]) + '\n')

    # Get recalls
    r1 = recall_score(y_test, y1, average='micro')
    r2 = recall_score(y_test, y2, average='micro')
    r3 = recall_score(y_test, y3, average='micro')
    r.append(','.join([str(r1), str(r2), str(r3)]) + '\n')

    # Get F1 scores
    f1 = f1_score(y_test, y1, average='micro')
    f2 = f1_score(y_test, y2, average='micro')
    f3 = f1_score(y_test, y3, average='micro')
    f.append(','.join([str(f1), str(f2), str(f3)]) + '\n')

# Print highest accuracy
print 'Highest Accuracy:', str(max([float(x.split(',')[0]) for x in a])*100)[0:4]+'%'

# Write data to appropriate files
with open('accuracy.csv', 'a') as file:
    for str in a: file.write(str)
with open('precision.csv', 'a') as file:
    for str in p: file.write(str)
with open('recall.csv', 'a') as file:
    for str in r: file.write(str)
with open('f1.csv', 'a') as file:
    for str in f: file.write(str)
