# Code Smells and Clean Code Practices

## Long functions
Functions longer than about 50 lines do too much. Extract cohesive helpers with descriptive names following the single responsibility principle.

## High cyclomatic complexity
Complexity above 10 makes code hard to test. Use guard clauses, lookup tables, polymorphism or strategy objects to reduce branching.

## Deep nesting
More than four nested levels hurts readability. Return early, invert conditions and extract inner blocks.

## Long parameter lists
More than five parameters suggest a missing abstraction. Group them in a dataclass or parameter object.

## Poor error handling
Bare except clauses, empty catch blocks and catching Exception or Throwable hide bugs. Catch specific exceptions and log or rethrow with context.

## Mutable default arguments
In Python a default of [] or {} is shared between calls. Use None and create the object inside the function.

## God classes
Classes with too many methods and responsibilities should be split by responsibility.

## Misc
Use a logging framework instead of print or System.out.println. Avoid wildcard imports and public mutable fields. Document public functions with docstrings or Javadoc. Resolve TODO and FIXME markers.
