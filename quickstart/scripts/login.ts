import {
	CognitoIdentityClient,
	CognitoIdentityClientConfig,
	GetOpenIdTokenForDeveloperIdentityCommand,
	GetOpenIdTokenForDeveloperIdentityCommandInput,
} from "@aws-sdk/client-cognito-identity";

const developerProviderName = 'developer-provider'
const cognitoIdentityClientConfig: CognitoIdentityClientConfig = {
	region: 'us-east-1'
}

const login = async (username: string) => {
	const input: GetOpenIdTokenForDeveloperIdentityCommandInput = {
		IdentityPoolId: 'us-east-1:5e6212d7-b907-4b6b-9b78-3cf761ff209f',
		Logins: {
			[developerProviderName]: username
		},
	}

	const client = new CognitoIdentityClient(cognitoIdentityClientConfig);
	const command = new GetOpenIdTokenForDeveloperIdentityCommand(input);
	const response = await client.send(command);
	return response
}

login('qqq').then(console.log).catch(console.error)
