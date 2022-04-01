import {
	CognitoIdentityClient,
	CognitoIdentityClientConfig,
	GetCredentialsForIdentityCommand,
	GetCredentialsForIdentityCommandInput,
} from "@aws-sdk/client-cognito-identity";

const cognitoIdentityClientConfig: CognitoIdentityClientConfig = {
	region: 'us-east-1'
}

const authorize =  async (IdentityId: string, Token: string) => {
	const input: GetCredentialsForIdentityCommandInput = {
		IdentityId,
		Logins: {
			'cognito-identity.amazonaws.com': Token
		}
	}

	const client = new CognitoIdentityClient(cognitoIdentityClientConfig);
	const command = new GetCredentialsForIdentityCommand(input);
	const response = await client.send(command);

	return response
}

authorize('us-east-1:20f149a0-8f7f-4d2b-b83e-11ffd950d4d7', 'ayJraWQiOiJ1cy1lYXN0LTExIiwidHlwIjoiSldTIiwiYWxnIjoiUlM1MTIifQ.eyJzdWIiOiJ1cy1lYXN0LTE6MjBmMTQ5YTAtOGY3Zi00ZDJiLWI4M2UtMTFmZmQ5NTBkNGQ3IiwiYXVkIjoidXMtZWFzdC0xOjVlNjIxMmQ3LWI5MDctNGI2Yi05Yjc4LTNjZjc2MWZmMjA5ZiIsImFtciI6WyJhdXRoZW50aWNhdGVkIiwiZGV2ZWxvcGVyLXByb3ZpZGVyIiwiZGV2ZWxvcGVyLXByb3ZpZGVyOnVzLWVhc3QtMTo1ZTYyMTJkNy1iOTA3LTRiNmItOWI3OC0zY2Y3NjFmZjIwOWY6dGVzdHgiXSwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkZW50aXR5LmFtYXpvbmF3cy5jb20iLCJleHAiOjE2NDg2NjI2MDksImlhdCI6MTY0ODY2MTcwOX0.Tbb6ScqNhh09KIRh0FqRA5FCkXgOQkPbEjq3AaWYWjKsZnXWne4snR_wz8yf_goht9UHaqRVyEOBouP6nMatexW_Ktmg74F_Q0mudDoUS0O6Dv7qtmk43HSIXpfjeo_OVFl55ccm8ZdmivhbDYiBUjEGwhxR5dNqg0jzgkn0uEUjPhORjzpySh9nraf878SU_LSk5iU79ikITWe_aT1v8U8_kmeAwoWB_ykEuRQ3oWZEc3RPaXl24usJ6dpKQ6Go6LMj62wMuMcrLLXaro9_X6G3sXMQuTY1Qy42RbVduce8ZHahQjOMwJ1id9CRYsY0gDZ3-A5soLQ1xn_986lRRA').then(console.log).catch(console.error)
