import * as ajv from 'ajv';

export interface RegistrySecrets {
	[registryAddress: string]: {
		username: string;
		password: string;
	};
}

/**
 * JSON schema validator for the private registry secrets (username and
 * password entries keyed by hostname:port registry addresses).
 */
export class RegistrySecretValidator {
	private registrySecretJsonSchema = {
		// Sample valid registrySecrets JSON contents:
		//   {  "docker.example.com": {"username": "ann", "password": "hunter2"},
		//      "https://idx.docker.io/v1/": {"username": "mck", "password": "cze14"}
		//   }
		type: 'object',
		patternProperties: {
			'.+': {
				type: 'object',
				properties: {
					username: { type: 'string' },
					password: { type: 'string' },
				},
				additionalProperties: false,
			},
		},
		additionalProperties: false,
	};
	private _ajv: ajv.Ajv;
	private _validateRegistrySecrets: ajv.ValidateFunction;

	constructor() {
		this._ajv = new ajv();
		this._validateRegistrySecrets = this._ajv.compile(
			this.registrySecretJsonSchema,
		);
	}

	/**
	 * Validate the given JSON object against the registry secrets schema.
	 * Throw an error if validation fails.
	 * @param parsedJson The result of calling JSON.parse()
	 * @returns The input object cast to the RegistrySecrets type if validation succeeds
	 */
	public validateRegistrySecrets(parsedJson: object): RegistrySecrets {
		const valid = this._validateRegistrySecrets(parsedJson);
		if (!valid) {
			throw new Error(this._ajv.errorsText());
		}
		return parsedJson as RegistrySecrets;
	}

	/**
	 * Call JSON.parse() on the given string, then validate the result against
	 * the registry secrets schema.
	 * @param json String containing a JSON representation of registry secrets
	 */
	public parseRegistrySecrets(json: string): RegistrySecrets {
		return this.validateRegistrySecrets(JSON.parse(json));
	}
}
