# zs-permission

Permissions provide information about the actions a user is allowed to perform against an API. This module
wraps a permissionArray - which contains the permission data - and provides methods to extract information
from it.

## Data format

The permissionArray is an array of permission objects. Each one ties a user to actions relevant to a specific object
or topic. Permission objects have three keys:

- target: A string denoting the type of object or procedure this permissions grants access to. By convention,
    a lower camel case target refers to a group of procedures, while upper camel case refers to object access.
- match: A query object. This is used to determine which objects a user has access to. When the PermissionSet is
    used for procedure access, this is a used to query against a 'virtual' object - see below.
- grant: An object denoting the set of authorized operations a user has against a matched object. This is typically a
    map of object properties or procedure names to true, but can also contain other data; see below for details.

A permissionArray represents the union of all its permissions; the user who owns it can access everything each permissions
allows him to. When multiple permissions can match an object, their grants are OR'd together.

## Usage

```javascript
var PermissionSet = require('zs-permission');

var permArray = [ {
	target: 'ordering',
	match: {
		brandId: 'zcafe'
	},
	grant: {
		get: true,
		cancel: true,
		void: true
	}
} ];
var permSet = new PermissionSet(permArray);
var grant = permSet.getTargetGrant('ordering', {
	brandId: 'zcafe',
	orderId: 'abcde12345'
});
```

getTargetGrant takes a target and an object to match the permission against; the match object of the permArray is used
as query against the object given to getTargetGrant. Since the targets are the same and the match...well, matches,
this permission's grant can be used.

getTargetGrant returns a Grant object, which contains information about all the grants that matched the query. It
is used to determine whether specific operations are permitted. The methods to use depend on what you are trying to
do. The use cases for permissions fall into two broad categories, which are outlined below.

### Permissions for object access

When dealing with direct object access through the API, permissions are used to restrict what users can do to those
objects, and to which parts of them. An example permission of this sort:

```javascript
{
	target: 'User',
	match: {
		ns: 'brand_zcafe'
	},
	grant: {
		read: true,
		readMask: true,
		update: true,
		updateMask: {
			phone: true,
			email: true
		}
	}
}
```

The user here is given permission to read the user data for any user belonging to the zcafe namespace, and may update
them as well - however, his updates may only touch the `phone` and `email` fields.

In order to validate that a given update is permissible, we must check both that the requesting user has both update
permission and that his updateMask allows all his update parameters.

```javascript
// var permSet, updateData both set
var user = getUserData(/*...*/);
var grant = permSet.getTargetGrant('User', user);
grant.check('update');  // Throws XError on failure
grant.checkMask('updateMask', updateData);  // Throws XError on failure
```

### Permissions for procedure access

Permission are also used to restrict access to API calls that don't pertain to accessing objects. In this case, the
argument to 'getTargetGrant' will be a 'virtual' object that represents the parameters to the procedure. The grant
will generally be a map of procedure names to true, representing the procedures. Consider the first example again:

```javascript
// An brand admin with access to view, cancel, and void any order in his brand
var permArray = [ {
	target: 'ordering',
	match: {
		brandId: 'zcafe'
	},
	grant: {
		get: true,
		cancel: true,
		void: true
	}
} ];
var permSet = new PermissionSet(permArray);
var orderPermissionData = {
	brandId: 'zcafe',
	orderId: 'abcde12345'
};

// Is user authorized to void a specific order?
permSet.getTargetGrant('ordering', orderPermissionData).check('void'); // returns true
// Is user authorized to submit a specific order?
permSet.getTargetGrant('ordering', orderPermissionData).check('submit'); // throws XError
// Is user authorized to submit an order for a different brand?
orderPermissionData.brandId = 'billy-bobs-burger-bayou';
permSet.getTargetGrant('ordering', orderPermissionData).check('void'); // throws XError
```

### Numeric permissions
There is occasionally a need to have authorization represented by a number instead of a boolean, such as when
restricting the size of a file a user may upload. There is a special syntax for this:

```javascript
var permSet = new PermissionSet([ {
	target: 'file',
	match: { /*...*/ },
	grant: {
		fileSize: {
			grantNumber: true,
			min: 0,
			max: 1000
		}
	}
} ])

var grant = permSet.getTargetGrant('file', { filename: 'thing.txt' });
grant.checkNumber('fileSize', 50);  // Returns true
grant.checkNumber('fileSize', 5000);  // Throws XError
```

### Admin permissions

A target can have the special value '*', which will match every target checked against it. Thus, an admin permission,
one that will be authorized to do anything, looks like this:

```javascript
{
	target: '*',
	match: {},
	grant: true
}
```
