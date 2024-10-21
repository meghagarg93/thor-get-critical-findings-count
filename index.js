const AWS = require('aws-sdk');
const inspector = new AWS.Inspector2({ region: 'us-west-2' });
const sns = new AWS.SNS({ region: 'us-west-2' });


async function getInspectorFindings(severity, resourceType) {
  // Retrieve the findings for the image from AWS Inspector

  var nextToken = undefined;
  var findings = []; // Array to store findings
  var Count = 0;
  do {
    var params = {
      filterCriteria: {
        severity: [{ comparison: "EQUALS", value: severity }],
        resourceType: [{ comparison: "EQUALS", value: resourceType }],
        findingStatus: [{ comparison: "EQUALS", value: "ACTIVE" }]
      },
      maxResults: 100,
      nextToken: nextToken
    };
    var res = await inspector.listFindings(params).promise();

    findings.push(...res.findings);

    Count += res.findings.length;
    nextToken = res.nextToken;
  }
  while (nextToken)

  // Extract finding titles from findings
  const findingTitles = findings.map(finding => finding.title);

  return { Count, findingTitles };
}



exports.handler = async (event, context) => {

  try {
    // Get the critical vulnerability counts 
    const { Count: latestECRCriticalCount, findingTitles: latestECRCriticalFindingTitles } = await getInspectorFindings("CRITICAL", "AWS_ECR_CONTAINER_IMAGE");
    console.log("in Main function: " + latestECRCriticalCount + latestECRCriticalFindingTitles);
    const { Count: latestLambdaCriticalCount, findingTitles: latestLambdaCriticalFindingTitles } = await getInspectorFindings("CRITICAL", "AWS_LAMBDA_FUNCTION");
    console.log("in Main function: " + latestLambdaCriticalCount + latestLambdaCriticalFindingTitles);
    const { Count: latestEC2CriticalCount, findingTitles: latestEC2CriticalFindingTitles } = await getInspectorFindings("CRITICAL", "AWS_EC2_INSTANCE");
    console.log("in Main function: " + latestEC2CriticalCount + latestEC2CriticalFindingTitles);




    // Publish the comparison result to the SNS topic
    const params = {
      TopicArn: 'arn:aws:sns:us-west-2:567434252311:Inspector_to_Email',
      Message: `Latest ECR Critical vulnerability Count is ${latestECRCriticalCount} \nLatest lambda Critical vulnerability Count is ${latestLambdaCriticalCount} \nLatest EC2 Critical vulnerability Count is ${latestEC2CriticalCount}`,
      Subject: `Thor Critical Vulnerability Count`,
    };
    await sns.publish(params).promise();

  }

  catch (error) {
    console.error('Error:', error);

    const params = {
      TopicArn: 'arn:aws:sns:us-west-2:567434252311:Inspector_to_Email',
      Message: `RError in Getting Critical Vulnerability Count:\n ${JSON.stringify(error)}`,
      Subject: `Error in Getting Critical Vulnerability Count`
    };
    await sns.publish(params).promise();
    throw error;
  }
};