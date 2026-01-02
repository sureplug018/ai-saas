// validators/match-password.validator.ts
import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';

@ValidatorConstraint({ name: 'MatchPassword', async: false })
export class MatchPasswordConstraint implements ValidatorConstraintInterface {
  validate(value: any, args: ValidationArguments): boolean {
    // Safely assert that constraints is an array and has at least one element
    const constraints = args.constraints as string[];
    const relatedPropertyName = constraints[0];

    if (!relatedPropertyName) {
      return false; // or throw, but returning false is safer
    }

    const relatedValue =
      typeof args.object === 'object' && args.object !== null
        ? (args.object as Record<string, unknown>)[relatedPropertyName]
        : undefined;
    return value === relatedValue;
  }

  defaultMessage(args: ValidationArguments): string {
    const constraints = args.constraints as string[];
    const relatedPropertyName = constraints[0] ?? 'specified field';

    return `${args.property} must match ${relatedPropertyName}`;
  }
}

export function MatchPassword(
  property: string,
  validationOptions?: ValidationOptions,
) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [property], // this is always a string array with one item
      validator: MatchPasswordConstraint,
    });
  };
}
