# Cloudtrail Parser

This is the script that executes the auto-tagging of resources 

The following dependancies must be installed for the script to work:

pigz - Parallel utility for gzip that greatly speeds unzipping Cloudtrail gzip files.

jq - Command line json parser that this utiility is built around.

It also assumes AWSCLI tools version 1.10 or higher

The steps the script follows are:

1. Clear AWS Environment variables, load administrator roles from adminroles.txt into an array, execute script one role at a time in a loop. 
2. Assume the role from the loop above, retrieve credentials, and load them into environment variables.
3. Obtain and prepare account ID and place in a variable $actid.
2. Query the AWS account for the names of S3 buckets that hold Cloudtrail logs.
3. Pull the Cloudtrail .gz logs from the S3 bucket to the instance drive and place in a folder called dumps.
4. Unzip the .gz files from the default AWS folder heriarchy and place all of the unzipped .json files in the top level of the dumps folder.
5. Loop through each .json file and extract the ARN's of users found in Cloudtrail logs
6. Loop through each .json file in the dumps folder and build the appropriate AWS CLI string to apply a tag to that resource and append the string to a file. Any new resources we would like to add to the autotagger would also need to have a new loop added that builds the string with the correct values.
7. Grep the file that all of the CLI strings were appended to in step 6 for just the events that we are interested in tagging. For instance, for EC2 the associate event is RunInstances.
8. Perform various formatting to prep the strings for execution at the CLI.
9. Import the custom tags from the custom tag names text file by joining the file that contains the extracted arn's with the document that contains the custom tags.
10. Perform some more formatting to leave just the strings for execution at command line.
11. Awk that file to create a file that has nothing but the custom tags and a separate file that contains just the arn's.
12. Awk all of the files to create one final file has the custom tag and the username in the correct places in the string.
13. Bash the file containing the formatted CLI strings for execution and clean up.


# Admin Roles Text File
This file is where you place the role that the script is to assume in the target account. The autotagger will execute accounts in the order in which they are placed in this file.
