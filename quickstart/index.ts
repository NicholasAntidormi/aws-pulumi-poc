import { createHash } from "crypto";
import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as apigateway from "@pulumi/aws-apigateway";
import {
	CognitoIdentityClient,
	CognitoIdentityClientConfig,
	GetOpenIdTokenForDeveloperIdentityCommand,
	GetOpenIdTokenForDeveloperIdentityCommandInput,
	GetCredentialsForIdentityCommand,
	GetCredentialsForIdentityCommandInput,
	DeleteIdentitiesCommand,
	DeleteIdentitiesCommandInput
} from "@aws-sdk/client-cognito-identity";

const getBody = (ev: any) =>
	!ev.body
		? ev.body
		: ev.isBase64Encoded
			? JSON.parse(Buffer.from(ev.body, 'base64').toString('utf8'))
			: JSON.parse(ev.body)

const developerProviderName = "developer-provider"
const cognitoIdentityClientConfig: CognitoIdentityClientConfig = {
	region: "us-east-1"
}

const identityPool = new aws.cognito.IdentityPool("identity-pool", {
	identityPoolName: "identity-pool",
	developerProviderName,
	allowUnauthenticatedIdentities: false,
});

const authenticatedRole = new aws.iam.Role("authenticatedRole", {
	assumeRolePolicy: {
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Principal: {
					Federated: "cognito-identity.amazonaws.com"
				},
				Action: "sts:AssumeRoleWithWebIdentity",
				Condition: {
					StringEquals: {
						"cognito-identity.amazonaws.com:aud": identityPool.id
					},
					"ForAnyValue:StringLike": {
						"cognito-identity.amazonaws.com:amr": "authenticated"
					}
				}
			}
		]
	}
});

const unauthenticatedRole = new aws.iam.Role("unauthenticatedRole", {
	assumeRolePolicy: {
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Principal: {
					Federated: "cognito-identity.amazonaws.com"
				},
				Action: "sts:AssumeRoleWithWebIdentity",
				Condition: {
					StringEquals: {
						"cognito-identity.amazonaws.com:aud": identityPool.id
					},
					"ForAnyValue:StringLike": {
						"cognito-identity.amazonaws.com:amr": "unauthenticated"
					}
				}
			}
		]
	}
});

const authenticatedRolePolicy = new aws.iam.RolePolicy("authenticatedRolePolicy", {
	role: authenticatedRole.id,
	policy: {
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Action: [
					"mobileanalytics:PutEvents",
					"cognito-sync:*",
					"cognito-identity:*"
				],
				Resource: [
					"*"
				]
			}
		]
	},
});

const unauthenticatedRolePolicy = new aws.iam.RolePolicy("unauthenticatedRolePolicy", {
	role: unauthenticatedRole.id,
	policy: {
		Version: "2012-10-17",
		Statement: [
			{
				Effect: "Allow",
				Action: [
					"mobileanalytics:PutEvents",
					"cognito-sync:*",
				],
				Resource: [
					"*"
				]
			}
		]
	},
});

const identityPoolRoleAttachment = new aws.cognito.IdentityPoolRoleAttachment("identityPoolRoleAttachment", {
	identityPoolId: identityPool.id,
	// roleMappings: [{
	//       identityProvider: "graph.facebook.com",
	//     ambiguousRoleResolution: "AuthenticatedRole",
	//     type: "Rules",
	//     mappingRules: [{
	//         claim: "isAdmin",
	//         matchType: "Equals",
	//         roleArn: authenticatedRole.arn,
	//         value: "paid",
	//     }],
	// }],
	roles: {
		authenticated: authenticatedRole.arn,
		unauthenticated: unauthenticatedRole.arn,
	},
});

const helloWorld = new aws.lambda.CallbackFunction("helloWorld", {
	callback: async (ev, ctx) => ({
		statusCode: 200,
		body: "Hello World!",
	})
});

const login = new aws.lambda.CallbackFunction("login", {
	callback: async (ev: any, ctx) => {
		const body = getBody(ev)
		const { username, password } = body || {}

		if (!username || !password) return { statusCode: 400, body: "Missing username or password" }

		// TODO: verify credentials

		const input: GetOpenIdTokenForDeveloperIdentityCommandInput = {
			IdentityPoolId: identityPool.id.get(),
			Logins: {
				[developerProviderName]: createHash('md5').update(username).digest("hex")
			},
			TokenDuration: 60 * 60
		}
		const client = new CognitoIdentityClient(cognitoIdentityClientConfig);
		const command = new GetOpenIdTokenForDeveloperIdentityCommand(input);
		const { Token, IdentityId } = await client.send(command);

		return {
			statusCode: 200,
			body: JSON.stringify({
				Token,
				IdentityId
			})
		};
	},
});

const authorize = new aws.lambda.CallbackFunction("authorize", {
	callback: async (ev: any, ctx) => {
		const { IdentityId, Token } = ev.headers || {}

		if (!IdentityId || !Token) return { statusCode: 400, body: "Missing username or password" }

		let effect = "Deny"

		if (IdentityId && Token) {
			const input: GetCredentialsForIdentityCommandInput = {
				IdentityId,
				Logins: {
					"cognito-identity.amazonaws.com": Token
				}
			}

			const client = new CognitoIdentityClient(cognitoIdentityClientConfig);
			const command = new GetCredentialsForIdentityCommand(input);
			try {
				await client.send(command);
				effect = "Allow"
			} catch (err) {
				effect = "Deny"
			}
		}

		return {
			principalId: "my-user",
			policyDocument: {
				Version: "2012-10-17",
				Statement: [
					{
						Action: "execute-api:Invoke",
						Effect: effect,
						Resource: ev.methodArn,
					},
				],
			}
		}
	}
});

const logout = new aws.lambda.CallbackFunction("logout", {
	callback: async (ev: any, ctx) => {
		const { IdentityId } = ev.headers || {}

		if (!IdentityId) return { statusCode: 400, body: "Missing identity id" }

		const input: DeleteIdentitiesCommandInput = {
			IdentityIdsToDelete: [IdentityId]
		}

		const client = new CognitoIdentityClient(cognitoIdentityClientConfig);
		const command = new DeleteIdentitiesCommand(input);
		const response = await client.send(command);

		return {
			statusCode: 200,
		};
	},
});

const api = new apigateway.RestAPI("api", {
	routes: [
		{
			path: "/login",
			method: "POST",
			eventHandler: login,
		},
		{
			path: "/hello-world",
			method: "GET",
			eventHandler: helloWorld,
		},
		{
			path: "/authorized/hello-world",
			method: "GET",
			eventHandler: helloWorld,
			authorizers: [
				{
					authType: "custom",
					parameterName: "Token",
					type: "request",
					identitySource: ["method.request.header.Token", "method.request.header.IdentityId"],
					handler: authorize,
				},
			],
		},
		{
			path: "/authorized/logout",
			method: "GET",
			eventHandler: logout,
			authorizers: [
				{
					authType: "custom",
					parameterName: "Token",
					type: "request",
					identitySource: ["method.request.header.Token", "method.request.header.IdentityId"],
					handler: authorize,
				},
			],
		}
	],
});

export const url = api.url;
