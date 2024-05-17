import pandas as pd
legitimate_urls = pd.read_csv(r"C:\\Users\\Lenovo\\Downloads\\Project_22\\Project_22\\Phishing-URL-Detection\\Phishing-URL-detection\\extracted_csv_files\\legitimate-urls.csv")
phishing_urls = pd.read_csv(r"C:\\Users\\Lenovo\\Downloads\\Project_22\\Project_22\\Phishing-URL-Detection\\Phishing-URL-detection\\extracted_csv_files\\phishing-urls.csv")
print(len(legitimate_urls))
print(len(phishing_urls))
urls = legitimate_urls._append(phishing_urls)
urls.head(5)
print(len(urls))
# print(urls.columns)


#  Removing Unnecessary columns
urls = urls.drop(urls.columns[[0,3,5]],axis=1) 
print(urls.columns)

# #### Since we merged two dataframes top 1000 rows will have legitimate urls and bottom 1000 rows will have phishing urls. So if we split the data now and create a model for it will overfit or underfit so we need to shuffle the rows before splitting the data into training set and test set

# shuffling the rows in the dataset so that when splitting the train and test set are equally distributed
urls = urls.sample(frac=1).reset_index(drop=True)


# #### Removing class variable from the dataset
urls_without_labels = urls.drop('label',axis=1)
urls_without_labels.columns
labels = urls['label']
#labels

# #### splitting the data into train data and test data
import random
random.seed(100)
from sklearn.model_selection import train_test_split
data_train, data_test, labels_train, labels_test = train_test_split(urls_without_labels, labels, test_size=0.20, random_state=100)
print(len(data_train),len(data_test),len(labels_train),len(labels_test))
print(labels_train.value_counts())
print(labels_test.value_counts())

# #### Checking the data is split in equal distribution or not
# ## Random Forest

from sklearn.ensemble import RandomForestClassifier
RFmodel = RandomForestClassifier()
RFmodel.fit(data_train,labels_train)
rf_pred_label = RFmodel.predict(data_test)
#print(list(labels_test)),print(list(rf_pred_label))

from sklearn.metrics import confusion_matrix,accuracy_score
cm2 = confusion_matrix(labels_test,rf_pred_label)
print(cm2)
print(accuracy_score(labels_test,rf_pred_label))

# Saving the model to a file
import pickle
file_name = "RandomForestModel.sav"
pickle.dump(RFmodel,open(file_name,'wb'))
