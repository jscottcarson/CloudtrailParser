#!/bin/bash

##############################################################################
###################### Section 1 - Set up Environment ########################
##############################################################################

# Remove any expired temporary environment variable keys
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN

#Load customer admin roles into an array to assume role in aws. These roles must have sts-assume role access enabled in AWS.
readarray admin < adminroles.txt

# For loop to execute tagging script looping through accounts who have roles added to the adminroles.txt file.
for line in ${admin[@]};
do

# Export to env variable for alter use
export current=$line

#Assume role using admin role loaded from adminroles.txt file above and write credentials to temporary file
aws sts assume-role  --role-arn $line  --role-session-name AutoTagger --query 'Credentials.{AWS_ACCESS_KEY_ID:AccessKeyId, AWS_SECRET_ACCESS_KEY:SecretAccessKey, AWS_SESSION_TOKEN:SessionToken}' > token.sh

# Remove the first and last lines,quotations, comma, replace colon with equals, remove blank spaces append the word export and source the file to the shell setting env variables.
sed -i -e '1d; $d' -e 's/"//g' -e 's/,//g' -e 's/: /=/g' -e 's/ //g' -e 's/^/export /' token.sh
. ./token.sh
rm -rf token.sh

###############################################################################
##################### Section 2 Get Account Specific Info #####################
###############################################################################

#Make a temporary folder
mkdir dumps

# Obtain and prepare account Id in a variable.
aws iam list-roles > roles.txt
cat roles.txt | jq '.Roles[].Arn' > rolespull.txt
rm -rf roles.txt

awk -F: '{print $5}' rolespull.txt > actid.txt
rm -rf rolespull.txt
awk '!a[$0]++' actid.txt > assets.tmp
rm -rf actid.txt
mv assets.tmp actid.txt
rm -rf assets.tmp

# Load account Id into a variable.
actid=`cat actid.txt`
rm -rf actid.txt



###############################################################################
########## Section 3 - Obtain Cloudtrail logging S3 Bucket Names ##############
###############################################################################

# Describe-Trail call to return trail descriptions in json format
aws cloudtrail --region us-west-1 describe-trails >> getbucketname.txt

# Pull bucketName values from json with jq and write to file
cat getbucketname.txt | jq '.trailList[].S3BucketName' >> bucketname.txt
rm -rf getbucketname.txt

#  Knock quotations of of the bucket name
cat bucketname.txt | awk '{print $1}' | tr -d \" >> bucketnameformat.txt
rm -rf bucketname.txt

#Load retrived bucket names into an array
declare -a lines
readarray -t lines <bucketnameformat.txt
rm -rf bucketnameformat.txt



######################################################################################################################################
############ Section 4 Use Bucket Names Obtained in Section 3 to Pull All Logs in Those Buckets to the Instance and unzip ############
######################################################################################################################################

#Iterate through the array of names and retrieve logs from identified Cloudtrail buckets
for line in ${lines[@]} ;
do
#aws s3 cp --recursive s3://$line/AWSLogs/$actid/CloudTrail/ap-northeast-1 dumps
#aws s3 cp --recursive s3://$line/AWSLogs/$actid/CloudTrail/ap-northeast-2 dumps
#aws s3 cp --recursive s3://$line/AWSLogs/$actid/CloudTrail/ap-south-1 dumps
#aws s3 cp --recursive s3://$line/AWSLogs/$actid/CloudTrail/ap-southeast-1 dumps
#aws s3 cp --recursive s3://$line/AWSLogs/$actid/CloudTrail/ap-southeast-2 dumps
#aws s3 cp --recursive s3://$line/AWSLogs/$actid/CloudTrail/eu-central-1 dumps
#aws s3 cp --recursive s3://$line/AWSLogs/$actid/CloudTrail/eu-west-1 dumps
#aws s3 cp --recursive s3://$line/AWSLogs/$actid/CloudTrail/sa-east-1 dumps
#aws s3 cp --recursive s3://$line/AWSLogs/$actid/CloudTrail/us-east-1 dumps
#aws s3 cp --recursive s3://$line/AWSLogs/$actid/CloudTrail/us-west-1 dumps
aws s3 cp --recursive s3://$line/AWSLogs/$actid/CloudTrail/us-west-2 dumps
done

#Move the log files from AWS's default directory sctructure to the /dumps folder
find dumps/* -type f -print0 | xargs -0 mv -t dumps/

#Delete the folders that make up the default AWS directory strucure in /dumps and leave only the .gz log files
rm -rf dumps/*/

echo ########################################################
echo ######################### unzip the logs ###############
echo ########################################################

#Loop through the .gz log files in /dumps unzip them and move the unzipped .json logs to the /ctlogs folder. Pigz is invoked for parallel unzipping and must be installed before the script runs.
for src in dumps/*.gz
do
unpigz -d -v $src
done




#########################################################################################################################################
######### Section 5 - Extract the Desired Event Information From the Unzipped and Formatted Logs and Form CLI Commands for Tagging ######
##### Edit this section by adding an additional loop (from for to second done below) to pull new events to tag ########################## 
#########################################################################################################################################


echo ###################################
echo Extract User Identities from Events
echo ###################################

for filename in dumps/*.json; do
 for ((i=0; i<=3; i++));
    do
      cat $filename | jq '.Records[]? | .userIdentity.arn' >> uid.txt
 done
done

#Delete duplicates, write results to assets.tmp file, rewrite temp file to uid.txt, remove assets.tmp
awk '!a[$0]++' uid.txt > assets.tmp
rm -rf uid.txt
mv assets.tmp uid.txt
rm -rf assets.tmp

# Trim quotations from file and move info to uidformat.txt
cat uid.txt | awk '{print $1}' | tr -d \" > uidformat.txt
rm -rf uid.txt

echo ##############################################################
echo Extract EC2 events
echo ##############################################################

#Iterate through CT logs pulled from S3 and extract EC2 only eventName, userName, instanceId and write output to assetstotag.txt file. >> append operator must be in place for iteration to write to file concurrently.
for filename in dumps/*.json; do
 for ((i=0; i<=3; i++)); do
cat $filename | jq '.Records[]? | .eventName + " " + "aws ec2 create-tags --region us-west-2 --resources" + " " + .responseElements.instancesSet.items[]?.instanceId? + " " + "--tags Key=CHS_Developer_Name,Value=" + .userIdentity.arn + " " + "Key=CHS_Resource_Group,Value=" + .userIdentity.arn' >> assetstotaglist.txt
 done
done

echo ##############################################################
echo Extract ELB events
echo ##############################################################

#Iterate through CT logs pulled from S3 and extract only ELB's to tag and append output to assetstotag.txt file. >> append
#operator must be in pla$
for filename in dumps/*.json; do
 for ((i=0; i<=3; i++)); do cat $filename | jq '.Records[]? | .eventName + " " + "aws elb add-tags --region us-west-2 --load-balancer-name" + " " + .requestParameters.loadBalancerName? + " " + "--tags Key=CHS_Developer_Name,Value=" + .userIdentity.arn + " " + "Key=CHS_Resource_Group,Value=" + .userIdentity.arn' >> assetstotaglist.txt
 done
done

for filename in dumps/*.json; do
 for ((i=0; i<=3; i++)); do cat $filename | jq '.Records[]? | .eventName + " " + "aws elbv2 add-tags --region us-west-2 --resource-arns" + " " + .responseElements.loadBalancers[]?.loadBalancerArn + " " + "--tags Key=CHS_Developer_Name,Value=" + .userIdentity.arn + " " + "Key=CHS_Resource_Group,Value=" + .userIdentity.arn' >> assetstotaglist.txt
 done
done


echo ###############################################################
echo Extract RDS Events
echo ###############################################################

#Iterate through CT logs pulled from S3 and extract only RDS to tag and append output to assetstotag.txt file. >> append operator must be in pla$
for filename in dumps/*.json; do
 for ((i=0; i<=3; i++)); do
cat $filename | jq '.Records[]? | .eventName + " " + "aws rds add-tags-to-resource --region us-west-2 --resource-name" + .requestParameters.dBInstanceIdentifier + " " + "--tags Key=CHS_Developer_Name,Value="
+ .userIdentity.arn + " " + "Key=CHS_Resource_Group,Value=" + .userIdentity.arn' >>  rdsassetstotaglist.txt
 done
done

#Insert the arn format for the RDS CLI tag
sed -i "s/\(resource-name\)/\1 arn:aws:rds:us-west-2:$actid:db:/g" rdsassetstotaglist.txt

echo ###############
echo Get Event names
echo ###############

#Grep for desired event names
grep -e 'CreateDBInstance' rdsassetstotaglist.txt > assets.txt
rm -rf rdsassetstotaglist.txt

cp uidformat.txt rdsuid.txt

grep -Ff rdsuid.txt assets.txt >> newfile.txt

# AWK to cut everything before the aws command
awk '{$1=""; print $0}' newfile.txt > assets1.txt
rm -rf newfile.txt

#SED to remove trailing quotations
sed 's/.\{1\}$//' assets1.txt > assets2.txt
rm -rf assets1.txt

#Awk to remove leading whitespace from all lines
awk -F";" -v OFS=";" '{for (i=1;i<=NF;i++) gsub (/^ */,"",$i);print}' assets2.txt > rdsassetstotag.txt
rm -rf assets2.txt

# Awk to remove all duplicates
awk '!a[$0]++' rdsassetstotag.txt > assets.tmp
mv assets.tmp rdsassetstotag.txt
rm -rf assets.tmp

# Sort and join the formatted extracted Arn's and the customer tag names document to have a list of strings that contain tags to apply to the environment
# Remove emails from the end of ARN's
awk 'BEGIN{FS=OFS="/"} NF--' rdsuid.txt > rdsuidformat.txt

# Awk to remove all duplicates from uidformat.txt
awk '!a[$0]++' rdsuidformat.txt > assets.tmp
mv assets.tmp rdsuidformat.txt
rm -rf assets.txt

sort rdsuidformat.txt -o rdsuidformat.txt
sort customertagnames.txt -o customertagnames.txt
join rdsuidformat.txt customertagnames.txt > tagstrings.txt
rm -rf rdsuidformat.txt

# Remove white spaces
sed 's/ *$//' tagstrings.txt

# AWK to remove all text before desired tag
awk '{$1=""; print $3}' tagstrings.txt > ftags.txt

# Cut everything after = leaving ARN only
cut -f1 -d"=" tagstrings.txt > finalarns.txt
rm -rf tagstrings.txt

awk '{$1=$1}1' finalarns.txt > farns.txt
awk '{$1=$1}1' rdsassetstotag.txt > fassets.txt

rm -rf finalarns.txt
rm -rf rdsassetstotag.txt


awk 'FNR==NR{a[FNR]=$0; n=NR; next} NR<=2*n{b[FNR]=$0; next} {for (i=1;i<=length(a);i++) gsub(a[i], b[i])g} 1' farns.txt ftags.txt fassets.txt > rdstotag.txt
rm -rf farns.txt ftags.txt fassets.txt

# Format the Developer name to only include the email address.
#Since we use / character in the regexp, we change delimiter of s command to !
#\(=[^=]=\) is a capture group that matches one = character followed by zero or more other characters followed by another = character. This part is needed to make sure there are two = characters before the to-be-dele$
#[^/]*/ matches whatever is between delimiters and the second delimiter
#\1 replaces the whole matched string with whatever matched the capture group # also remove the email address by removing all after last slash

sed -i -e 's!\(=[^=]*=\)[^/]*/!\1!' -e 's%/[^/]*$%/%' rdstotag.txt

#####################################################################
# Format the Resource Group tag to only include the desired app tag
#####################################################################

# Remove the last slash leaving just the app name as a tag
awk '{sub(/.$/,"")}1' rdstotag.txt > tmp.txt
mv tmp.txt rdstotag.txt
rm -rf tmp.txt

# Sed to add developer label back to s3. It gets cropped in an above action
sed -i 's/\[{Key=\b/&CHS_Developer_Name,Value=/' rdstotag.txt

cat rdstotag.txt >> finalassetstotag.txt
rm -rf rdstotag.txt



echo ################################################################
echo Extract Autoscaling Events
echo ################################################################

#Iterate through CT logs pulled from S3 and extract only Autoscaling events to tag and write output to asassetstotag.txt file
for filename in dumps/*.json; do
 for ((i=0; i<=3; i++));do
cat $filename | jq '.Records[]? | .eventName + " " + "aws autoscaling create-or-update-tags --region us-west-2 --tags ResourceId=" + .requestParameters.autoScalingGroupName  + ",ResourceType=auto-scaling-group,Key=CHS_Developer_Name,
Value=" + .userIdentity.arn + "," + "PropagateAtLaunch=true" + " " + "ResourceId=" + .requestParameters.autoScalingGroupName + ",ResourceType=auto-scaling-group,Key=CHS_Resource_Group,Value=" +
.userIdentity.arn + ",PropagateAtLaunch=true"' >> astotaglist.txt
done
done

# Extract autoscaling only specific events to tag for
grep -e 'CreateAutoScalingGroup' astotaglist.txt >> asassets.txt
rm -rf astotaglist.txt

grep -Ff uidformat.txt asassets.txt >> asnewfile.txt

echo ########################
echo Formatting Autoscaling Tags
echo ########################

# AWK to cut everything before the aws command
awk '{$1=""; print $0}' asnewfile.txt > asassets1.txt
rm -rf asnewfile.txt

#SED to remove trailing quotations
sed 's/.\{1\}$//' asassets1.txt > asassets2.txt
rm -rf asassets1.txt

#Awk to remove leading whitespace from all lines
awk -F ";" -v OFS=";" '{for (i=1;i<=NF;i++) gsub (/^ */,"",$i);print}' asassets2.txt > astotag.txt
rm -rf asassets2.txt

# Awk to remove all duplicates
awk '!a[$0]++' astotag.txt > asassets.tmp
rm -rf astotag.txt
mv asassets.tmp astotag.txt
rm -rf asassets.tmp

# Sort and join the formatted extracted Arn's and the customer tag names document to have a list of strings that contain tags to apply to the environment
# Remove emails from the end of ARN's
awk 'BEGIN{FS=OFS="/"} NF--' uidformat.txt > asuidformat.txt

# Awk to remove all duplicates from uidformat.txt
awk '!a[$0]++' asuidformat.txt > asassets.tmp
rm -rf asuidformat.txt
mv asassets.tmp asuidformat.txt
rm -rf asassets.txt

# Sort uidformat.txt & customertagnames.txt for joining to be left with only a list of desired tags.
sort asuidformat.txt -o asuidformat.txt
sort customertagnames.txt -o customertagnames.txt
join asuidformat.txt customertagnames.txt > astagstrings.txt
rm -rf asuidformat.txt

# Remove white spaces
sed -i 's/ *$//' astagstrings.txt

# AWK to remove all text before desired tag producing a final tag file
awk '{$1=""; print $3}' astagstrings.txt > asftags.txt

# Cut everything after = leaving ARN only to produce a final ARN file
cut -f1 -d"=" astagstrings.txt > asfinalarns.txt
rm -rf astagstrings.txt

# Awk for formatting
awk '{$1=$1}1' asfinalarns.txt > asfarns.txt
awk '{$1=$1}1' astotag.txt > asfassets.txt

# Clean up
rm -rf asfinalarns.txt
rm -rf astotag.txt

#FNR==NR{a[FNR]=$0; next}
#This saves all the lines in file2 in array a.
#FNR is the number of lines read from the current file. NR is the number of lines read in total. Thus, if FNR==NR, we are reading the first named file, file2.  a[FNR]=$0 adds the current line, denoted $0, into array a under the key FNR.
#The command next tells awk to skip the remaining commands and start over on the next line.

#NR<=length(a)+FNR{b[FNR]=$0; next}
#This saves all the lines of file1 in array b.
#Here, we use a similar test, NR<=length(a)+FNR, to determine if we are reading the second file. b[FNR]=$0 adds the current line, denoted $0, into array b under the key FNR.
#The command next tells awk to skip the remaining commands and start over on the next line.

#for (i=1;i<=length(a);i++) gsub(a[i], b[i])
#If we get here, we are reading the third file. This replaces any text matching a line in file2 with the corresponding text from file1.
#The loop for (i=1;i<=length(a);i++) loops over the line number of every line in array a.
#gsub(a[i], b[i]) replaces any occurrence of text a[i] with the text b[i].
#Note that the text in file2 is treated as a regular expression. If you need to have any regex-active characters in this file, they should be escaped.

#1
#This is awk's cryptic short-hand for print-the-line.

awk 'FNR==NR{a[FNR]=$0; n=NR; next} NR<=2*n{b[FNR]=$0; next} {for (i=1;i<=length(a);i++) gsub(a[i], b[i])g} 1' asfarns.txt asftags.txt asfassets.txt > astotag.txt
rm -rf asfarns.txt asftags.txt asfassets.txt

# Format the Developer name to only include the email address.Since we use / character in the regexp, we change delimiter of s command to !
#\(=[^=]=\) is a capture group that matches one = character followed by zero or more other characters followed by another = character. This part is needed to make sure there are two = characters before the to-be-deleted substring
#[^/]*/ matches whatever is between delimiters and the second delimiter \1 replaces # also remove the trailing email address by removing all after last slash

sed -i -e 's!\(=[^=]*=\)[^/]*/!\1!' -e 's%/[^/]*$%/%'  astotag.txt

#####################################################################
# Format the Resource Group tag to only include the desired app tag
#####################################################################


# Remove the last slash leaving just the app name as a tag
awk '{sub(/.$/,"")}1' astotag.txt > astmp.txt
mv astmp.txt astotag.txt
rm -rf astmp.txt

# Add Autoscaling specific formatting
# Format for CLI, add back what was cut unecessarily Remove all after last slash to remove the email address from the Resource Group tag 
# Add Propogate at Launch to end of line to complete the syntax for CLI
sed -i -e 's!\(=[^=]*=\)[^/]*/!\1!' -e's/ResourceType=/ResourceType=auto-scaling-group,Key=CHS_Developer_Name,Value=/g' -e 's%/[^/]*$%/%' -e 's/$/,PropagateAtLaunch=true/' -e 's/Key=CHS_Developer_Name,Value=auto-scaling-group,//g' astotag.txt


# Write Autscaling formatted CLI commands to main tagging file
cat astotag.txt >> finalassetstotag.txt
rm -rf astotag.txt


  
echo ################################################################
echo Extract S3 Events
echo ################################################################

#Iterate through CT logs pulled from S3 and extract only S3 events to tag and append output to assetstotag.txt file. >> append operator must be in pla$
for filename in dumps/*.json; do
 for ((i=0; i<=3; i++));do
cat $filename | jq '.Records[]? | .eventName + " "  + "aws s3api put-bucket-tagging --region us-west-2 --bucket" + " "  + .requestParameters.bucketName + " "  + "--tagging" + " " +  "TagSet=[{Key=CHS_Developer_Name,Value=" + .userIdentity.arn + "},{Key=CHS_Resource_Group,Value=" + .userIdentity.arn + "}]"' >> s3assetstotaglist.txt
done
done

# Extract S3 only specific events to tag for
grep -e 'CreateBucket' s3assetstotaglist.txt >> s3assets.txt
rm -rf s3assetstotaglist.txt

grep -Ff uidformat.txt s3assets.txt >> s3newfile.txt

echo ########################
echo Formatting S3 Tags
echo ########################

# AWK to cut everything before the aws command
awk '{$1=""; print $0}' s3newfile.txt > s3assets1.txt
rm -rf s3newfile.txt

#SED to remove trailing quotations
sed 's/.\{1\}$//' s3assets1.txt > s3assets2.txt
rm -rf s3assets1.txt

#Awk to remove leading whitespace from all lines
awk -F ";" -v OFS=";" '{for (i=1;i<=NF;i++) gsub (/^ */,"",$i);print}' s3assets2.txt > s3assetstotag.txt
rm -rf s3assets2.txt

# Awk to remove all duplicates
awk '!a[$0]++' s3assetstotag.txt > s3assets.tmp
rm -rf s3assetstotag.txt
mv s3assets.tmp s3assetstotag.txt
rm -rf s3assets.tmp

# Sort and join the formatted extracted Arn's and the customer tag names document to have a list of strings that contain tags to apply to the environment
# Remove emails from the end of ARN's
awk 'BEGIN{FS=OFS="/"} NF--' uidformat.txt > s3uidformat.txt

# Awk to remove all duplicates from uidformat.txt
awk '!a[$0]++' s3uidformat.txt > s3assets.tmp
rm -rf s3uidformat.txt
mv s3assets.tmp s3uidformat.txt
rm -rf s3assets.txt

# Sort uidformat.txt & customertagnames.txt for joining to be left with only a list of desired tags.
sort s3uidformat.txt -o s3uidformat.txt
sort customertagnames.txt -o customertagnames.txt
join s3uidformat.txt customertagnames.txt > s3tagstrings.txt
rm -rf s3uidformat.txt

# Remove white spaces
sed 's/ *$//' s3tagstrings.txt

# AWK to remove all text before desired tag producing a final tag file
awk '{$1=""; print $3}' s3tagstrings.txt > s3ftags.txt

# Cut everything after = leaving ARN only to produce a final ARN file
cut -f1 -d"=" s3tagstrings.txt > s3finalarns.txt
rm -rf s3tagstrings.txt

# Awk for formatting
awk '{$1=$1}1' s3finalarns.txt > s3farns.txt
awk '{$1=$1}1' s3assetstotag.txt > s3fassets.txt

# Clean up
rm -rf s3finalarns.txt
rm -rf s3assetstotag.txt

#FNR==NR{a[FNR]=$0; next}
#This saves all the lines in file2 in array a.
#FNR is the number of lines read from the current file. NR is the number of lines read in total. Thus, if FNR==NR, we are reading the first named file, file2.  a[FNR]=$0 adds the current line, denoted $0, into array a under the key FNR.
#The command next tells awk to skip the remaining commands and start over on the next line.

#NR<=length(a)+FNR{b[FNR]=$0; next}
#This saves all the lines of file1 in array b.
#Here, we use a similar test, NR<=length(a)+FNR, to determine if we are reading the second file. b[FNR]=$0 adds the current line, denoted $0, into array b under the key FNR.
#The command next tells awk to skip the remaining commands and start over on the next line.

#for (i=1;i<=length(a);i++) gsub(a[i], b[i])
#If we get here, we are reading the third file. This replaces any text matching a line in file2 with the corresponding text from file1.
#The loop for (i=1;i<=length(a);i++) loops over the line number of every line in array a.
#gsub(a[i], b[i]) replaces any occurrence of text a[i] with the text b[i].
#Note that the text in file2 is treated as a regular expression. If you need to have any regex-active characters in this file, they should be escaped.

#1
#This is awk's cryptic short-hand for print-the-line.

awk 'FNR==NR{a[FNR]=$0; n=NR; next} NR<=2*n{b[FNR]=$0; next} {for (i=1;i<=length(a);i++) gsub(a[i], b[i])g} 1' s3farns.txt s3ftags.txt s3fassets.txt > s3assetstotag.txt
rm -rf s3farns.txt s3ftags.txt s3fassets.txt

# Format the Developer name to only include the email address.Since we use / character in the regexp, we change delimiter of s command to !
#\(=[^=]=\) is a capture group that matches one = character followed by zero or more other characters followed by another = character. This part is needed to make sure there are two = characters before the to-be-deleted substring
#[^/]*/ matches whatever is between delimiters and the second delimiter \1 replaces the whole matched string with whatever matched the capture group \(=[^=]=\)

sed -i 's!\(=[^=]*=\)[^/]*/!\1!' s3assetstotag.txt

#####################################################################
# Format the Resource Group tag to only include the desired app tag
#####################################################################

# Remove the email address from arn by removing all after last slash
sed -i 's%/[^/]*$%/%' s3assetstotag.txt

# Remove the last slash leaving just the app name as a tag
awk '{sub(/.$/,"")}1' s3assetstotag.txt > s3tmp.txt
mv s3tmp.txt s3assetstotag.txt
rm -rf s3tmp.txt

# Final S3 Specific Formatting
# Sed to add developer label back to s3. It gets cropped in an above action
sed -i 's/\[{Key=\b/&CHS_Developer_Name,Value=/' s3assetstotag.txt

#Sed to add ending characters to s3
awk '{print $0"}]"}' s3assetstotag.txt
sed -i -e 's/$/}]"/' -e 's/TagSet/"TagSet/g' s3assetstotag.txt

cat s3assetstotag.txt >> finalassetstotag.txt
rm -rf s3assetstotag.txt

################################# Format all not formatted in its section and add to assetstotag.txt ########################################

echo #######################################################
echo Narrowing Extracted Events to Only Those Desired to Tag
echo #######################################################

#Grep for desired event names. For every for loop added above add the corresponding specific event below to pull specifics from general list of all events returned
grep -e 'RunInstances' -e 'CreateLoadBalancer'  assetstotaglist.txt > assets.txt
rm -rf assetstotaglist.txt

grep -Ff uidformat.txt assets.txt > newfile.txt

echo ##########################
echo Formatting Everything Else
echo ##########################

# AWK to cut everything before the aws command
awk '{$1=""; print $0}' newfile.txt > assets1.txt
rm -rf newfile.txt

#SED to remove trailing quotations
sed 's/.\{1\}$//' assets1.txt > assets2.txt
rm -rf assets1.txt

#Awk to remove leading whitespace from all lines
awk -F ";" -v OFS=";" '{for (i=1;i<=NF;i++) gsub (/^ */,"",$i);print}' assets2.txt > assetstotag.txt
rm -rf assets2.txt

# Awk to remove all duplicates
awk '!a[$0]++' assetstotag.txt > assets.tmp
rm -rf assetstotag.txt
mv assets.tmp assetstotag.txt
rm -rf assets.tmp

# Sort and join the formatted extracted Arn's and the customer tag names document to have a list of strings that contain tags to apply to the environment
# Remove emails from the end of ARN's
awk 'BEGIN{FS=OFS="/"} NF--' uidformat.txt > uidtemp.tmp
rm -rf uidformat.txt
mv uidtemp.tmp uidformat.txt
rm -rf uidtemp.tmp

# Awk to remove all duplicates from uidformat.txt
awk '!a[$0]++' uidformat.txt > assets.tmp
rm -rf uidformat.txt
mv assets.tmp uidformat.txt
rm -rf assets.txt

# Sort uidformat.txt & customertagnames.txt for joining to be left with only a list of desired tags.
sort uidformat.txt -o uidformat.txt
sort customertagnames.txt -o customertagnames.txt
join uidformat.txt customertagnames.txt > tagstrings.txt
rm -rf uidformat.txt

# Remove white spaces
sed -i 's/ *$//' tagstrings.txt

# AWK to remove all text before desired tag producing a final tag file
awk '{$1=""; print $3}' tagstrings.txt > ftags.txt

# Cut everything after = leaving ARN only to produce a final ARN file
cut -f1 -d"=" tagstrings.txt > finalarns.txt
rm -rf tagstrings.txt

# Awk for formatting
awk '{$1=$1}1' finalarns.txt > farns.txt
awk '{$1=$1}1' assetstotag.txt > fassets.txt

# Clean up
rm -rf finalarns.txt
rm -rf assetstotag.txt

#FNR==NR{a[FNR]=$0; next}
#This saves all the lines in file2 in array a.
#FNR is the number of lines read from the current file. NR is the number of lines read in total. Thus, if FNR==NR, we are reading the first named file, file2.  a[FNR]=$0 adds the current line, denoted $0, into array a under the key FNR.
#The command next tells awk to skip the remaining commands and start over on the next line.

#NR<=length(a)+FNR{b[FNR]=$0; next}
#This saves all the lines of file1 in array b.
#Here, we use a similar test, NR<=length(a)+FNR, to determine if we are reading the second file. b[FNR]=$0 adds the current line, denoted $0, into array b under the key FNR.
#The command next tells awk to skip the remaining commands and start over on the next line.

#for (i=1;i<=length(a);i++) gsub(a[i], b[i])
#If we get here, we are reading the third file. This replaces any text matching a line in file2 with the corresponding text from file1.
#The loop for (i=1;i<=length(a);i++) loops over the line number of every line in array a.
#gsub(a[i], b[i]) replaces any occurrence of text a[i] with the text b[i].
#Note that the text in file2 is treated as a regular expression. If you need to have any regex-active characters in this file, they should be escaped.

#1
#This is awk's cryptic short-hand for print-the-line.

awk 'FNR==NR{a[FNR]=$0; n=NR; next} NR<=2*n{b[FNR]=$0; next} {for (i=1;i<=length(a);i++) gsub(a[i], b[i])g} 1' farns.txt ftags.txt fassets.txt > assetstotag.txt
rm -rf farns.txt ftags.txt fassets.txt

# Format the Developer name to only include the email address.Since we use / character in the regexp, we change delimiter of s command to !
#\(=[^=]=\) is a capture group that matches one = character followed by zero or more other characters followed by another = character. This part is needed to make sure there are two = characters before the to-be-deleted substring
#[^/]*/ matches whatever is between delimiters and the second delimiter \1 replaces the whole matched string with whatever matched the capture group \(=[^=]=\)

# Remove the email address from arn by removing all after last slash
sed -i -e 's!\(=[^=]*=\)[^/]*/!\1!' -e 's%/[^/]*$%/%' assetstotag.txt

#####################################################################
# Format the Resource Group tag to only include the desired app tag
#####################################################################

# Remove the last slash leaving just the app name as a tag
awk '{sub(/.$/,"")}1' assetstotag.txt > tmp.txt
mv tmp.txt assetstotag.txt
rm -rf tmp.txt

# Add all tags not formatted in their respective section to master tag file.
cat assetstotag.txt >> finalassetstotag.txt
rm -rf assetstotag.txt





echo #############
echo applying tags
echo #############




#######################################################################################################################
########################################### Section 6 - Begin Applying Tags ###########################################
#######################################################################################################################

# Unset environment variables and reset in case the above takes longer than the first keys are good for
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN

#Assume role using admin role loaded from adminroles.txt file above and write credentials to temporary file
aws sts assume-role  --role-arn $current  --role-session-name AutoTagger --query 'Credentials.{AWS_ACCESS_KEY_ID:AccessKeyId, AWS_SECRET_ACCESS_KEY:SecretAccessKey, AWS_SESSION_TOKEN:SessionToken}' > token.sh

# Remove the first and last lines,quotations, comma, replace colon with equals, remove blank spaces append the word export and source the file to the shell setting env variables.
sed -i -e '1d; $d' -e 's/"//g' -e 's/,//g' -e 's/: /=/g' -e 's/ //g' -e 's/^/export /' token.sh
. ./token.sh
rm -rf token.sh

bash finalassetstotag.txt &>/dev/null
rm -rf finalassetstotag.txt

#delete dumps temp file
rm -rf dumps

# Clear environment variables
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN
unset current

# Repeat the loop for next Role ARN pulled in section 1 until none are left.
done

echo Complete
