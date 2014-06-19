var doc_utils = require('objtools');
var commonQuery = require('common-query');
var ZSError = require('zs-error');

/* A Permission object tracks a set of permissions.  It allows creating subsets of
 * permissions for manipulation, and tracking the hierarchy used to create a given
 * Permission object. */

/**
 * Permission constructor.  Represents a set of permissions.
 *
 * @param permArray Array Array of permission objects
 */
var Permission = function(permArray) {
	if(!permArray) permArray = [];
	if(permArray.permArray) permArray = permArray.permArray;
	this.topLevelPermission = this;
	this.permArray = permArray;
};

// Internal function that processes numeric grant entries into min/max objects
function grantNumbersToObjects(grantObj) {
	if(grantObj && typeof grantObj == 'object' && !grantObj.grantNumber) {
		var newObj = {};
		Object.keys(grantObj).forEach(function(k) {
			newObj[k] = grantNumbersToObjects(grantObj[k]);
		});
		return newObj;
	} else if(typeof grantObj == 'number') {
		return {
			grantNumber: true,
			min: grantObj,
			max: grantObj
		};
	} else {
		return grantObj;
	}
}

function targetMatches(targetMatch, targetObj) {
	if(typeof targetMatch == 'string' && targetMatch[0] == '{') {
		try {
			targetMatch = JSON.parse(targetMatch);
			if(!targetMatch) return false;
		} catch (ex) {
			return false;
		}
	}
	var r = commonQuery.queryMatches('Permission', targetMatch, targetObj);
	if(r instanceof ZSError) return false;
	return r;
}

/**
 * Combines multiple grants together.
 *
 * @param grant1...n mixed Grant object contents to combine (not Grant objects, the actual data)
 * @return object The combined grant
 */
function combineGrants() {
	function grantType(grant) {
		if(grant === true) return 'true';
		if(typeof grant == 'object' && grant && grant.grantNumber) return 'grantnum';
		if(typeof grant == 'object' && grant) return 'object';
		return 'false';
	}
	function combine2(grant1, grant2) {
		var type1 = grantType(grant1);
		var type2 = grantType(grant2);
		if(type1 == 'true' || type2 == 'true') return true;
		if(type1 == 'false') return grant2;
		if(type2 == 'false') return grant1;
		if(type1 == 'object' && type2 == 'object') {
			var newObj = {};
			var allKeySet = {};
			Object.keys(grant1).concat(Object.keys(grant2)).forEach(function(k) { allKeySet[k] = true; });
			Object.keys(allKeySet).forEach(function(k) {
				if(grant1[k] === undefined) newObj[k] = grant2[k];
				else if(grant2[k] === undefined) newObj[k] = grant1[k];
				else newObj[k] = combine2(grant1[k], grant2[k]);
			});
			return newObj;
		}
		if(type1 == 'grantnum' && type2 == 'grantnum') {
			return {
				grantNumber: true,
				min: Math.min(grant1.min, grant2.min),
				max: Math.max(grant1.max, grant2.max)
			};
		}
		if(type1 == 'object') return grant1;
		if(type2 == 'object') return grant2;
		return false;
	}
	if(!arguments.length) return false;
	else if(arguments.length == 1) return arguments[0];
	else return Array.prototype.slice.call(arguments, 0).reduce(function(accum, cur) {
		return combine2(accum, cur);
	}, false);
}

/**
 * Grant constructor.
 *
 * @param grantObj object The grant object data
 */
var Grant = function(grantObj) {
	this.grant = grantObj;
};

// Make the Grant constructor available on the Permission object
Permission.Grant = Grant;

/**
 * Returns the data associated with a Grant object.
 *
 * @return object The data.
 */
Grant.prototype.asObject = function() {
	return this.grant;
};

/**
 * Checks whether the grant contains the given field.
 *
 * @param k mixed Either a string (which may be a dot-separated path) naming a path in the grant
 * to check, or an object mapping keys to true (arbitrarily structured), all of which are checked
 * for.
 * @return boolean Whether or not the given field is contained.
 */
Grant.prototype.has = function(k) {
	if(this.grant === true) return true;
	if(typeof this.grant != 'object') return false;
	if(typeof k == 'string') {
		var match = {};
		match[k] = true;
		return doc_utils.matchStructuredDocument(this.grant, match);
	} else if(typeof k == 'object') {
		return doc_utils.matchStructuredDocument(this.grant, k);
	} else return false;
};

// Alias has to can
Grant.prototype.can = Grant.prototype.has;

/**
 * Returns a sub-part of a grant.  May return boolean true (if all permissions granted) or
 * boolean false (if no permission is granted) in the sub-part.
 *
 * @param k string A dot-separated path in the grant data
 * @return mixed The contents of the grant portion, or true/false
 */
Grant.prototype.get = function(k) {
	function gget(keyParts, grantObj) {
		if(grantObj === true) return true;
		if(!keyParts.length) return grantObj;
		if(typeof grantObj == 'object' && grantObj) {
			return gget(keyParts.slice(1), grantObj[keyParts[0]]);
		}
		return false;
	}
	return gget(k.split('.'), this.grant);
};

/**
 * Returns the maximum of a numeric value in a grant.
 *
 * @param k string A path in the grant
 * @return number The max, or null
 */
Grant.prototype.max = function(k) {
	var val = this.get(k);
	if(val === true) return Infinity;
	if(!val || typeof val != 'object' || !val.grantNumber || typeof val.max != 'number') return null;
	return val.max;
};

/**
 * Returns the minimum of a numeric value in a grant.
 *
 * @param k string A path in the grant
 * @return number The min, or null
 */
Grant.prototype.min = function(k) {
	var val = this.get(k);
	if(val === true) return -Infinity;
	if(!val || typeof val != 'object' || !val.grantNumber || typeof val.min != 'number') return null;
	return val.min;
};

/**
 * Returns a mask/whitelist at the given path in the grant.
 *
 * @param k string A path in the grant
 * @return mixed The mask at that path in the grant (can be boolean true or false as well)
 */
Grant.prototype.getMask = function(k) {
	var mask = this.get(k);
	if(mask !== true && typeof mask != 'object') return false;
	return mask;
};

/**
 * Returns all permissions (including sub-components of permissions) that match
 * a given target.  Note: This should not be used for most permissions operations.
 * Use getTargetGrant() instead unless there is a good reason not to.
 *
 * @param targetType string The target type to find
 * @param target object Target object to match
 * @return Array An array of permission data and permission components (of children) that
 * match the given target.
 */
Permission.prototype.getTargetMatching = function(targetType, target) {
	function permParts(p) {
		var matches = false;
		if(p.target === undefined) matches = true;
		else if(Array.isArray(p.target)) {
			p.target.forEach(function(t) {
				if(targetMatches(t, target)) matches = true;
			});
		} else {
			matches = targetMatches(p.target, target);
		}
		if(matches) {
			var ret = [p];
			if(p.children) {
				var children = p.children;
				if(!Array.isArray(children)) children = [children];
				children.forEach(function(child) {
					var childParts = permParts(child);
					if(childParts && childParts.length) Array.prototype.push.apply(ret, childParts);
				});
			}
			return ret;
		} else {
			return [];
		}
	}
	var ret = [];
	this.permArray.forEach(function(p) {
		if((p.type === 'target' || p.type === undefined) && (p.targetType === targetType || p.targetType === '*')) {
			var pParts = permParts(p);
			if(pParts && pParts.length) Array.prototype.push.apply(ret, pParts);
		}
	});
	return ret;
};

/**
 * Returns a Grant instance with the combined grants for all permissions matching
 * a given target.
 *
 * @param targetType string The target type to find
 * @param target object Target object to match
 * @return Grant The Grant object pertaining to the given target
 */
Permission.prototype.getTargetGrant = function(targetType, target) {
	var parts = this.getTargetMatching(targetType, target);
	var grants = parts.map(function(p) {
		return p.grant;
	}).filter(function(g) {
		return g !== undefined;
	});
	if(!grants || !grants.length) return new Grant({});
	return new Grant(combineGrants.apply(null, grants.map(function(g) {
		return grantNumbersToObjects(g);
	})));
};

/**
 * Substitutes query $var expressions in the targets of each permission.
 *
 * @param vars object Map from variable name to value
 */
Permission.prototype.substituteTargetVars = function(vars) {
	this.permArray.forEach(function(perm) {
		if(perm.type === 'target' || perm.type === undefined) {
			if(perm.target) {
				var target;
				if(typeof perm.target == 'string' && perm.target[0] == '{') {
					try {
						target = JSON.parse(perm.target);
					} catch(ex) {}
				} else target = perm.target;
				if(target && typeof target == 'object') {
					perm.target = target;
					commonQuery.substituteVars(perm.target, vars, true);
				}
			}
		}
	});
};


/**************************************************************
 * EVERYTHING BELOW THIS LINE IS ONLY USED FOR PERMISSIONS NOT USING THE TARGET SYSTEM
 * YOU PROBABLY SHOULD NOT BE USING ANY OF THIS!
 * IT IS INCLUDED IN CASE THERE IS A VERY GOOD REASON
 **************************************************************/


/**
 * Returns whether or not a permission is of type 'global_admin' .
 * Note: This is not checked for target-type permissions.  Prefer to use target-type
 * permissions when possible.
 *
 * @return boolean Whether or not a permission of type 'global_admin' is contained
 */
Permission.prototype.hasGlobalAdmin = function() {
	return this.getTopLevel().hasExact( { type: 'global_admin' } );
};

/**
 * Returns all of the values of a given field on the permission.
 *
 * @param fieldName string The name of the field
 * @return Array All of the values of that field on contained permissions
 */
Permission.prototype.getFieldValues = function(fieldName) {
	var ret = [];
	this.permArray.forEach(function(p) {
		if(p[fieldName] !== undefined) ret.push(p[fieldName]);
	});
	return ret;
};

/**
 * Checks whether or not any of the given permissions have a field equal to the
 * given field value.
 *
 * @param fieldName string The name of the field to check.
 * @param fieldValue mixed The value to check for.
 * @return boolean Whether or not the field value is found.
 */
Permission.prototype.hasFieldValue = function(fieldName, fieldValue) {
	var ret = false;
	this.permArray.forEach(function(p) {
		if(p[fieldName] === fieldValue) ret = true;
	});
	return ret || this.hasGlobalAdmin();
};

/**
 * Returns the maximum of a numeric field in the permission.  Prefer to use Grant.max()
 * if possible.
 *
 * @param fieldName string The name of the field to check
 * @return number The max value, or null if the field was not found
 */
Permission.prototype.getNumberMax = function(fieldName) {
	var ret = null;
	this.permArray.forEach(function(p) {
		if(p[fieldName] !== undefined && (ret === null || p[fieldName] > ret)) ret = p[fieldName];
	});
	return ret;
};

/**
 * Checks for a boolean field value.
 *
 * @param fieldName string The name of the field to check for.
 * @param boolDefault boolean Defaults to false.  If set to true, then a falsy value on the permission is searched for.
 * @return boolean Whether or not the value is found.
 */
Permission.prototype.hasBoolean = function(fieldName, boolDefault) {
	boolDefault = !!boolDefault;
	var ret = boolDefault;
	this.permArray.forEach(function(p) {
		if(p[fieldName] !== undefined && (!!p[fieldName]) != boolDefault) ret = !boolDefault;
	});
	return ret || this.hasGlobalAdmin();
};

/**
 * Returns the combined masks of all contained permissions.  Prefer to use Grant.getMask() if possible.
 *
 * @param fieldName string The field name of the mask
 * @return mixed The combined mask
 */
Permission.prototype.getMask = function(fieldName) {
	if(this.hasGlobalAdmin()) return true;
	var whitelists = [];
	this.permArray.forEach(function(p) {
		if(p[fieldName]) whitelists.push(p[fieldName]);
	});
	return doc_utils.combineWhitelists.apply(doc_utils, whitelists);
};

/**
 * Returns the data of all contained permissions.
 *
 * @return Array The data.
 */
Permission.prototype.asArray = function() {
	return this.permArray;
};

/**
 * Returns the parent Permission (ie, the Permission that .getAll() was called on
 * to get this Permission.
 *
 * @return Permission
 */
Permission.prototype.getParent = function() {
	return this.parentPermission;
};

/**
 * Returns the top-level Permission of the permission hierarchy, created by .getAll().
 *
 * @return Permission
 */
Permission.prototype.getTopLevel = function() {
	return this.topLevelPermission;
};

/**
 * Constructs a derived Permission object from a subset of permissions in this object.
 *
 * @param newPermArray Array Array of permission data, which must be a subset of this Permission's array.
 * @return Permission The permission subset.
 */
Permission.prototype.permissionSubset = function(newPermArray) {
	var newPerms = new Permission(newPermArray);
	newPerms.parentPermission = this;
	newPerms.topLevelPermission = this.topLevelPermission || this;
	return newPerms;
};

/**
 * This function will return a new Permission object which matches the given fields.
 * Matching is determined as follows:
 * 1. A permission must match all fields given for the permission to match.
 * 2. If a permission does not contain any of the given fields, the permission does not match.
 * 3. If a field is the special value "*", the field is always considered to match.
 * 4. If the corresponding field in the permission is an array, the field matches if ANY of the array values equal the given field.
 * 5. Other field equality is determined by === .
 * 6. Matching is only done one-layer deep.
 *
 * @param fields object Fields to match
 * @return Permission The subset of this Permission that matches the given fields.
 */
Permission.prototype.getAll = function(fields) {
	if(!fields) return this;
	var permArray = this.permArray;
	var ret = [];
	if(permArray.forEach) permArray.forEach(function(perm) {
		function fieldMatches(givenField, fieldName) {
			if(givenField === undefined) return true;
			var permField = perm[fieldName];
			if(permField === undefined) return false;
			if(permField === '*') return true;
			if(Array.isArray(permField)) {
				if(permField.indexOf(givenField) != -1) return true;
			} else {
				return permField === givenField;
			}
			return false;
		}
		var matchesAll = true;
		for(var key in fields) {
			if(!fieldMatches(fields[key], key)) {
				matchesAll = false;
				break;
			}
		}
		if(matchesAll) ret.push(perm);
	});
	return this.permissionSubset(ret);
};

// Alias of getAll
Permission.prototype.getMatching = Permission.prototype.getAll;

/**
 * Returns the subset of permissions that are supersets of the given fields.
 * Ie, the given fields must contain (and match) at least every key in the permission,
 * and there may be extra given fields.  The is different from the above getAll(),
 * in that getAll() requires every field in fields to be contained by the permission.
 *
 * @param fields object The fields to match
 * @return Permission The matching permissions
 */
Permission.prototype.getSuper = function(fields) {
	var ret = [];
	this.permArray.forEach(function(p) {
		var matches = true;
		for(var key in p) {
			if(fields[key] !== p[key]) matches = false;
		}
		if(matches) ret.push(p);
	});
	return this.permissionSubset(ret);
};

/**
 * Returns true iff there is at least one matching permission, as determined by getAll().
 * Prefer to use Grant.has() if possible.
 *
 * @param fields object The fields to match
 * @return boolean Whether or not there is at least one matching permission
 */
Permission.prototype.has = function(fields) {
	if(this.getAll(fields).asArray().length > 0 || this.hasGlobalAdmin()) return true;
	return false;
};

/**
 * Returns whether or not a permission is contained that exactly matches the given fields.
 *
 * @param fields object The fields to match
 * @return boolean Whether or not a match is found
 */
Permission.prototype.hasExact = function(fields) {
	var ret = false;
	var matching = this.getMatching(fields);
	matching.asArray().forEach(function(p) {
		var matches = true;
		for(var key in p) {
			if(p[key] !== fields[key]) matches = false;
		}
		if(matches) ret = true;
	});
	return ret;
};

/**
 * Returns the array of permission data to use when stringifying JSON.
 */
Permission.prototype.toJSON = function() {
	return this.permArray;
};

module.exports = Permission;

