import requests
import yaml


def upload_plan_gitlab():
    gitlab_url = 'https://gitlab.com/ahmed.aissa/plans/-/raw/main/baseline.yaml'

    # Make a GET request to download the file
    response = requests.get(gitlab_url)

    # Check if the request was successful
    if response.status_code == 200:
        # Read the YAML content
        print(response.text)
        yaml_data = yaml.safe_load(response.text)

        # Process the YAML data as needed
        print(yaml_data)

        return yaml_data
    else:
        print(f"Failed to download YAML file. Status code: {response.status_code}")
        return None


def main():
    # Call the upload_plan_gitlab function
    yaml_data = upload_plan_gitlab()

    # Check if YAML data is retrieved successfully
    if yaml_data:
        print("YAML file downloaded successfully!")
        # Process the YAML data further if needed
    else:
        print("Failed to download YAML file.")

if __name__ == "__main__":
    main()