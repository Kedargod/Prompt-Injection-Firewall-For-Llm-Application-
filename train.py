from firewall import classifier

classifier.train("data/train.csv")
print("Model trained and saved to model.joblib")
