# Creating a CI/CD pipeline with FirecREST

## Goal of the exercise

Create a CI/CD pipeline that will run in Piz Daint through FirecREST.

## Prerequisites

- **Basic python and git knowledge**: The task involves very basic Python.
Even if you have experience with another programming language, you'll likely find the task manageable.
- **CSCS user account**: The pipeline is alredy configured for access to Piz Daint but it requires minimal changes to customize for a different machine.
- **Github account**: The CI will utilize resources from your GitHub account, so make sure you have one.
- **Basic CI/CD understanding**: Familiarity with basic concepts of Continuous Integration and Continuous Deployment processes is recommended.

## Getting Started

1. **Create an OIDC client, if you haven't already.**

1. **Create a GitHub repository**
    - Copy all the files of this folder in the root folder of your repo.
    - The workflows will be disabled by default in your repo so go ahead and enable them in the "Actions" tab of your repository.

1. **Inspect the code that will be tested:**
    Take a moment to review the code in the `dist` folder. This is the code that will be tested in the CI/CD pipeline.

    Right now there is nothing meaningful there, but you can add your own tests.

1. **Configure CI/CD Pipeline:**
    - Open the CI configuration file (`.github/workflows/ci.yml`) and, with the help of the comments, try to understand the different steps that are already configured. The only change is the last line of and change it to your project on the machine ` --account=your_project`.
    - Set up the secrets that are used in the pipeline in your account. The variables are needed are `FIRECREST_CLIENT_ID`, `FIRECREST_CLIENT_SECRET`, `FIRECREST_URL` and `AUTH_TOKEN_URL`.

1. **Review Results:**
    Once you've configured the pipeline, commit your changes and push them to your GitHub repository.
    You can follow the progress of the workflow in the "Actions" tab and ensure that the tests ran successfully, and the job was submitted to Piz Daint without issues.

1. **[Optional] Apply this to your own codes:**
    If you are familiar with another CI platform and you have code that you would like to test on Piz Daint we can help you set up the CI.

## Additional Resources

- [OIDC Dashboard](https://oidc-dashboard-prod.cscs.ch/)
- [pyFirecrest documentation](https://pyfirecrest.readthedocs.io)
- [How to set up secrets in Github Actions](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions)
- [FirecREST documentation](https://firecrest.readthedocs.io)
