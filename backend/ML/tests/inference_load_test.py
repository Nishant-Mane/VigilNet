from inference import IDSModel


def main():
    model = IDSModel(model_dir="model")

    print("Model loaded:", model.model is not None)
    print("Imputer loaded:", model.imputer is not None)
    print("Selected features loaded:", model.selected_features is not None)
    print("Decision threshold loaded:", model.decision_threshold is not None)

    print("Feature count:", len(model.selected_features))


if __name__ == "__main__":
    main()
