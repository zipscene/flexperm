/** zs-permission.js - v0.0.21 - Tue, 11 Nov 2014 21:00:13 GMT */
!function(e){if("object"==typeof exports&&"undefined"!=typeof module)module.exports=e();else if("function"==typeof define&&define.amd)define([],e);else{var o;"undefined"!=typeof window?o=window:"undefined"!=typeof global?o=global:"undefined"!=typeof self&&(o=self),(o.ZSModule||(o.ZSModule={})).ZSPermission=e()}}(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(_dereq_,module,exports){
var ZSError = (typeof window !== "undefined" ? window.ZSModule.ZSError : typeof global !== "undefined" ? global.ZSModule.ZSError : null);
var objtools = (typeof window !== "undefined" ? window.ZSModule.objtools : typeof global !== "undefined" ? global.ZSModule.objtools : null);

/**
 * Grant constructor.
 *
 * @param grantObj object The grant object data
 * @param targetType string Optional target type used to generate the grant
 * @param target object Optional target used to generate the grant
 */
var Grant = function(grantObj, targetType, target) {
	this.grant = grantObj;
	this._targetType = targetType;
	this._target = target;
};

module.exports = Grant;

Grant.prototype.getTargetType = function() {
	return this._targetType;
};

Grant.prototype.getTarget = function() {
	return this._target;
};

Grant.prototype.createSubgrantFromMask = function(mask) {
	if(typeof mask == 'string') {
		mask = this.getMask(mask);
	}
	return new Grant(mask, this._targetType, this._target);
};

Grant.prototype.createSubgrantFromMasks = function(masks) {
	var maskObjs = [];
	for(var i = 0; i < masks.length; i++) {
		if(typeof masks[i] == 'string') {
			maskObjs.push(this.getMask(masks[i]));
		} else {
			maskObjs.push(masks[i]);
		}
	}
	var mask = combineGrants(maskObjs);
	return new Grant(mask, this._targetType, this._target);
};

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
 * @param k mixed Can be a string naming a dot-separated path to check for, or an array of strings,
 * or an object mapping dot-separated paths to boolean true.
 * @return boolean Whether or not the given field is contained.
 */
Grant.prototype.has = function(k, prefix) {
	if(!prefix) prefix = '';
	var self = this;
	if(this.grant === true) return true;
	if(typeof this.grant != 'object') return false;

	function checkPath(path) {
		return objtools.checkMaskPath(self.grant, path);
	}

	if(typeof k == 'string') {
		return checkPath(prefix + k);
	} else if(Array.isArray(k)) {
		for(var i = 0; i < k.length; i++) {
			if(!checkPath(prefix + k[i])) return false;
		}
		return true;
	} else if(typeof k == 'object' && k) {
		for(var key in k) {
			if(k[key] && !checkPath(prefix + k[key])) return false;
		}
		return true;
	} else {
		return false;
	}
};

// Alias has to can
Grant.prototype.can = Grant.prototype.has;

// Like has(), but returns null on success and an instance of ZSError on failure
// Prefer to use this instead of has() if possible so errors are returned in a consistent format
Grant.prototype.check = function(k, prefix) {
	if(!prefix) prefix = '';
	if(typeof k == 'string') {
		if(!this.has(k, prefix)) {
			if(this._targetType) {
				return new ZSError(ZSError.ACCESS_DENIED, 'Access denied trying to ' + prefix + k + ' a target of type ' + this._targetType, { grantKey: prefix + k, targetType: this._targetType, target: this._target });
			} else {
				return new ZSError(ZSError.ACCESS_DENIED, 'Access denied trying to ' + prefix + k);
			}
		}
	} else if(Array.isArray(k)) {
		for(var i = 0; i < k.length; i++) {
			var e = this.check(k[i], prefix);
			if(e) return e;
		}
	} else if(typeof k == 'object' && k) {
		for(var key in k) {
			var e2 = this.check(key, prefix);
			if(e2) return e2;
		}
	} else {
		return new ZSError(ZSError.INTERNAL_ERROR, 'Supplied invalid key to permission checking function', { key: k });
	}
	return null;
};

/**
 * Checks an object against a mask that's a subcomponent of this grant.  If any field is in the object
 * that is not matched by the grant, this returns a ZSError.  Otherwisee, it returns null.
 * The mask argument can either be a mask object or a string path to a mask in this grant.
 */
Grant.prototype.checkMask = function(mask, obj) {
	var maskPath = null;
	if(typeof mask == 'string') {
		maskPath = mask;
		mask = this.getMask(maskPath);
	}

	if(mask === true) return null;
	if(!mask) return new ZSError(ZSError.ACCESS_DENIED, 'Access denied in ' + (maskPath || 'mask') + ' for objects of type ' + this._targetType, { grantKey: maskPath, targetType: this._targetType, target: this._target });
	if(!obj || typeof obj != 'object') return new ZSError(ZSError.INTERNAL_ERROR, 'Tried to do permissions match against non-object');

	var maskedOutFields = objtools.getMaskedOutFields(obj, mask);
	if(maskedOutFields.length) return new ZSError(ZSError.ACCESS_DENIED, 'Access denied in ' + (maskPath || 'mask') + ' for objects of type ' + this._targetType + ' to access field ' + maskedOutFields[0], { grantKey: maskPath, targetType: this._targetType, target: this._target });
	return null;
};

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
 * Combines this grant with the given other grant.  The result overwrites this grant's data.
 */
Grant.prototype.combine = function(otherGrant) {
	this.grant = combineGrants(this.grant, otherGrant.grant);
};


/**
 * Combines multiple grants together.
 *
 * @param grant1...n mixed Grant object contents to combine (not Grant objects, the actual data)
 * @return object The combined grant
 */
// This code is copied and modified from objtools addMasks() function
function combineGrants() {
	var resultMask = false;

	// Adds a single mask (fromMask) into the resultMask mask in-place.  toMask should be an object.
	// If the resulting mask is a boolean true, this function returns true.  Otherwise, it returns toMask.
	function addMask(resultMask, newMask) {
		var key;

		if(resultMask === true) return true;
		if(newMask === true) {
			resultMask = true;
			return resultMask;
		}
		if(objtools.isScalar(newMask)) return resultMask;
		if(objtools.isScalar(resultMask)) {
			resultMask = objtools.deepCopy(newMask);
			return resultMask;
		}

		if(Array.isArray(resultMask)) {
			resultMask = { _: resultMask[0] || false };
		}
		if(Array.isArray(newMask)) {
			newMask = { _: newMask[0] || false };
		}

		// Handle the case of grant numbers
		if(resultMask.grantNumber && newMask.grantNumber) {
			resultMask.min = Math.min(resultMask.min, newMask.min);
			resultMask.max = Math.max(resultMask.max, newMask.max);
			return resultMask;
		} else if(resultMask.grantNumber || newMask.grantNumber) {
			return false;	// Mismatched types ... can't really handle it better
		}

		// If there are keys that exist in result but not in the newMask, and the result mask has a _ key (wildcard), combine
		// the wildcard mask with the new mask, because in the existing result mask, that key has the wildcard permissions
		if(newMask._ !== undefined) {
			for(key in resultMask) {
				if(key === '_') continue;
				if(newMask[key] === undefined) {
					resultMask[key] = addMask(resultMask[key], newMask._);
				}
			}
		}

		// same here ... also, copy over or merge fields
		for(key in newMask) {
			if(key === '_') continue;
			if(resultMask[key] !== undefined) {
				resultMask[key] = addMask(resultMask[key], newMask[key]);
			} else if(resultMask._ !== undefined) {
				resultMask[key] = addMask(objtools.deepCopy(newMask[key]), resultMask._);
			} else {
				resultMask[key] = objtools.deepCopy(newMask[key]);
			}
		}
		// fill in the _ key that we skipped earlier
		if(newMask._ !== undefined) {
			if(resultMask._ !== undefined) resultMask._ = addMask(resultMask._, newMask._);
			else resultMask._ = objtools.deepCopy(newMask._);
		}

		return resultMask || false;
	}

	for(var argIdx = 0; argIdx < arguments.length; argIdx++) {
		resultMask = addMask(resultMask, arguments[argIdx]);
		if(resultMask === true) return true;
	}
	return resultMask || false;
}

Grant.combineGrants = combineGrants;
Grant.combineMasks = combineGrants;


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

Grant.grantNumbersToObjects = grantNumbersToObjects;

},{"objtools":"objtools","zs-error":"zs-error"}],2:[function(_dereq_,module,exports){
var commonQuery = (typeof window !== "undefined" ? window.ZSModule.commonQuery : typeof global !== "undefined" ? global.ZSModule.commonQuery : null);
var objtools = (typeof window !== "undefined" ? window.ZSModule.objtools : typeof global !== "undefined" ? global.ZSModule.objtools : null);
var Grant = _dereq_('./grant');
var md5 = (typeof window !== "undefined" ? window.md5 : typeof global !== "undefined" ? global.md5 : null);
var ZSError = (typeof window !== "undefined" ? window.ZSModule.ZSError : typeof global !== "undefined" ? global.ZSModule.ZSError : null);

function PermissionSet(permArray, permissionVars, _raw) {
	if(_raw) return;
	this._array = permArray;
	this._vars = permissionVars;
	this._hashCache = {};	// cache of hashes by target type
	this.rebuild();
}
module.exports = PermissionSet;

PermissionSet.Grant = Grant;

// Rebuilds the internal structures used to do permission lookups after updating the permissions array or vars
PermissionSet.prototype.rebuild = function() {
	this._tree = buildPermissionTree(this._array, this._vars);
	this._hashCache = {};
	// Precompute hashes
	if(typeof md5 !== 'undefined') {
		for(var targetType in this._tree) {
			this.getHash(targetType);
		}
	}
};

// Returns the Grant object representing the permissions the principal has on the target
PermissionSet.prototype.getTargetGrant = function(targetType, target) {
	var tree = this._tree[targetType];
	var wildcardTree = this._tree['*'];
	var grantObjects = [];
	if(tree) Array.prototype.push.apply(grantObjects, getPermissionTreeMatchingGrants(tree, target));
	if(wildcardTree) Array.prototype.push.apply(grantObjects, getPermissionTreeMatchingGrants(wildcardTree, target));
	if(!grantObjects.length) return new Grant(false, targetType, target);
	if(grantObjects.length == 1) return new Grant(grantObjects[0], targetType, target);
	return new Grant(Grant.combineGrants.apply(null, grantObjects), targetType, target);
};

// Returns the original array representation of the permission set
// If this is modified, you must call .rebuild() to update the internal structures
PermissionSet.prototype.asArray = function() {
	return this._array;
};

PermissionSet.prototype.toJSON = function() {
	return this._array;
};

// Returns an array of all fields that are queried on for a target of the given type.  These are all the fields that
// are necessary to do permissions evaluation on an object.
PermissionSet.prototype.getTargetQueryFields = function(targetType) {
	var tree = this._tree[targetType];
	var wildcardTree = this._tree['*'];
	var fieldSet = {};
	if(tree) getPermissionTreeQueryFields(tree, targetType, fieldSet);
	if(wildcardTree) getPermissionTreeQueryFields(wildcardTree, targetType, fieldSet);
	return Object.keys(fieldSet);
};

// Returns a hash of the permissions relevant to the given target type (or all target types if not given)
PermissionSet.prototype.getHash = function(targetType) {
	var targetTypeStr = targetType ? targetType : '___';
	if(this._hashCache[targetTypeStr]) return this._hashCache[targetTypeStr];
	var array = this.asArray();
	if(targetType) {
		array = array.filter(function(p) {
			return p.targetType === targetType;
		});
		if(!array.length) return 'xxxxxxxx';
	}
	var hash = md5(JSON.stringify(array));
	this._hashCache[targetTypeStr] = hash;
	return hash;
};

// Creates a function that will filter an object.  The function will ensure that the permission set
// contains the permission given in grantPath, and will filter the object by the mask at maskName.
// The function will return null if there is no permission to access the object.
PermissionSet.prototype.createFilterByMask = function(targetType, grantPath, maskName) {
	var self = this;
	return function(obj) {
		var grant = self.getTargetGrant(targetType, obj || {});
		if(!grant.has(grantPath)) return null;
		var mask = grant.getMask(maskName);
		return objtools.filterObj(obj, mask);
	};
};

// Checks whether the given query can be executed on an object of targetType
// The query must be in commonQuery form
// queryOptions can include 'fields' (an array of fields requested) and sort (an array of fields to sort by) and limit (checked against the user's max limit for results)
// Any malformed options detected will result in an error
// To check for a permission on the grant other than 'read' and 'query' (for example, 'count'), supply queryTypeGrantName (can also be an array, which is OR'd together)
// Returns null on success or ZSError on error
PermissionSet.prototype.checkExecuteQuery = function(targetType, query, queryOptions, queryTypeGrantName) {
	// get the query grant for this query
	var queryGrant = this.getTargetGrant(targetType, commonQuery.queryToObject(query));

	// Make sure the user has read or query permission for the query
	var accessError;
	if(queryTypeGrantName) {
		if(!Array.isArray(queryTypeGrantName)) queryTypeGrantName = [queryTypeGrantName];
		for(var i = 0; i < queryTypeGrantName; i++) {
			if(i === 0 || accessError) {
				accessError = queryGrant.check(queryTypeGrantName[i]);
			}
		}
	} else {
		accessError = queryGrant.check('read') && queryGrant.check('query');
	}
	if(accessError) return accessError;

	// Make sure the user can read all fields used in the query
	accessError = queryGrant.check(commonQuery.getQueriedFields(targetType, query), 'readMask.');
	if(accessError) return accessError;

	// Make sure the user can read all fields requested to be returned (not strictly necessary, but will generate helpful errors early)
	if(queryOptions && queryOptions.fields) {
		if(!Array.isArray(queryOptions.fields)) return new ZSError(ZSError.BAD_REQUEST, 'Permission-Set checkExecuteQuery got badly formatted fields option', { fields: queryOptions.fields });
		accessError = queryGrant.check(queryOptions.fields, 'readMask.');
		if(accessError) return accessError;
	}

	// Make sure the user can read or query on all sort fields
	if(queryOptions && queryOptions.sort) {
		if(!Array.isArray(queryOptions.sort)) return new ZSError(ZSError.BAD_REQUEST, 'Permission-Set checkExecuteQuery got badly formatted sort option', { sort: queryOptions.sort });
		accessError = queryGrant.check(queryOptions.sort.map(function(f) {
			if(typeof f != 'string') return '';
			if(f[0] == '-' || f[0] == '+') return f.slice(1);
			else return f;
		}), 'readMask.');
	}
	if(accessError) return accessError;

	// Make sure the requested limit is within the user's maximum
	var maxLimit = queryGrant.max('maxQueryLimit');
	if(maxLimit !== null && maxLimit !== undefined && maxLimit !== Infinity && queryOptions && typeof queryOptions.limit == 'number') {
		if(queryOptions.limit > maxLimit) {
			return new ZSError(ZSError.ACCESS_DENIED, 'The requested limit of ' + queryOptions.limit + ' is above your maximum allowed of ' + maxLimit + ' for type ' + targetType);
		}
	}

	return null;
};

// Returns all info about this object to reconstruct it without reprocessing
PermissionSet.prototype.serialize = function() {
	return {
		_array: this._array,
		_vars: this._vars,
		_tree: this._tree,
		_hashCache: this._hashCache
	};
};

PermissionSet.deserialize = function(ser) {
	var p = new PermissionSet(null, null, true);
	p._array = ser._array;
	p._vars = ser._vars;
	p._tree = ser._tree;
	p._hashCache = ser._hashCache;
	return p;
};



// Returns an array of grants that match the target in the given permission tree
function getPermissionTreeMatchingGrants(permTree, targetObject) {
	var grants = [];
	function addMatchingGrants(tree) {
		var i, j;
		for(i = 0; i < tree.perms.length; i++) {
			var perm = tree.perms[i];
			if(!perm.target || commonQuery.queryMatches('Permission', perm.target, targetObject)) {
				grants.push(tree.perms[i].grant);
			}
		}
		for(i = 0; i < tree.matches.length; i++) {
			var match = tree.matches[i];
			var objFieldValue = objtools.getPath(targetObject, match.field);
			if(objFieldValue !== undefined) {
				var subtree;
				if(Array.isArray(objFieldValue)) {
					for(j = 0; j < objFieldValue.length; j++) {
						subtree = match.values[objFieldValue[j]];
						if(subtree) {
							addMatchingGrants(subtree);
						}
					}
				} else {
					subtree = match.values[objFieldValue];
					if(subtree) {
						addMatchingGrants(subtree);
					}
				}
			}
		}
	}
	addMatchingGrants(permTree);
	return grants;
}

// Adds to the fieldSet passed in each field used for queries in the given tree
function getPermissionTreeQueryFields(permTree, targetType, fieldSet) {
	function addBranch(tree) {
		var i, j, queryFields;
		// Add fields used by remaining target queries
		if(tree.perms) {
			for(i = 0; i < tree.perms.length; i++) {
				if(tree.perms[i].target) {
					queryFields = commonQuery.getQueriedFields(targetType || null, tree.perms[i].target);
					for(j = 0; j < queryFields.length; j++) {
						fieldSet[queryFields[j]] = true;
					}
				}
			}
		}
		// Add fields used by each match, and recurse
		if(tree.matches) {
			for(i = 0; i < tree.matches.length; i++) {
				var match = tree.matches[i];
				fieldSet[match.field] = true;
				if(match.values) {
					for(var val in match.values) {
						var subtree = match.values[val];
						addBranch(subtree);
					}
				}
			}
		}
	}
	addBranch(permTree);
}


/* For efficient lookups, we build a tree of targets out of the permission array.
It can only build this tree for for portions of queries which are AND'd exact matches.
The tree will look like this:
{
	User: {
		perms: [ ... ],
		matches: [
			{
				field: 'ns',
				values: {
					'zs': {
						perms: [ ... ],
						matches: [ ... ]
					}
				}
			}
		]
	}
}
*/
function buildPermissionTree(permArray, permissionVars) {
	var i, perm, targetType;

	// We will treat each target type separately.  Construct a map from target types to the contained permissions.
	var permissionsByTargetType = {};
	for(i = 0; i < permArray.length; i++) {
		perm = permArray[i];
		if(perm.type == 'target' || !perm.type) {
			if(perm.targetType) {
				if(permissionsByTargetType[perm.targetType]) {
					permissionsByTargetType[perm.targetType].push(perm);
				} else {
					permissionsByTargetType[perm.targetType] = [perm];
				}
			}
		}
	}

	// Build up a tree for each target type
	function buildTargetTypeTree(permArray) {

		var field;

		// When building the tree, we want to have to iterate through as few fields at each node as possible.
		// Calculate which fields are matched on, and sort by number of occurrences in the permission array (greatest to least)
		var numMatchesByField = {};
		function addPermissionsMatches(permArray) {
			var i, perm, field;
			for(i = 0; i < permArray.length; i++) {
				perm = permArray[i];
				if(perm.target && typeof perm.target == 'object') {
					for(field in perm.target) {
						if(typeof perm.target[field] != 'object' && field[0] != '$') {
							numMatchesByField[field] = (numMatchesByField[field] || 0) + 1;
						}
					}
				}
				if(Array.isArray(perm.children)) {
					addPermissionsMatches(perm.children);
				}
			}
		}
		addPermissionsMatches(permArray);
		var fieldOrder = [];
		for(field in numMatchesByField) {
			fieldOrder.push(field);
		}
		fieldOrder.sort(function(a, b) {
			return numMatchesByField[b] - numMatchesByField[a];
		});
		// fieldOrder now contains the fields that we will check, in order from most matches to least matches

		var tree = {
			perms: [],
			matches: []
		};

		function addPermissionToTree(target, grant) {
			var i, j, field, fieldValue;

			// keep track of the "remaining" fields in the target not addressed by the tree
			var remainingTarget = {};
			for(field in target) {
				remainingTarget[field] = target[field];
			}

			// traverse the tree in order of the fields to find where to insert this permission
			// this is a pointer to the current tree node
			var curTree = tree;
			for(i = 0; i < fieldOrder.length; i++) {

				// Get the field name and value from its position in the ordered field list
				field = fieldOrder[i];
				fieldValue = remainingTarget[field];

				// If the field is not matched, or is not a simple scalar match, move on to the next field
				if(fieldValue === undefined || typeof fieldValue == 'object') {
					continue;
				}

				// Find or create the match that corresponds to this field
				var curMatch = null;
				for(j = 0; j < curTree.matches.length; j++) {
					if(curTree.matches[j].field == field) {
						curMatch = curTree.matches[j];
					}
				}
				if(!curMatch) {
					curMatch = {
						field: field,
						values: {}
					};
					curTree.matches.push(curMatch);
				}

				// If the value of this match already exists, use that as the next curTree.  Otherwise create one.
				if(curMatch.values[fieldValue]) {
					curTree = curMatch.values[fieldValue];
				} else {
					curTree = {
						perms: [],
						matches: []
					};
					curMatch.values[fieldValue] = curTree;
				}

				// Since this field match is now handled by the tree, remove it from the remaining target
				delete remainingTarget[field];
			}

			// curTree now points to the part of the tree where the permission should be added, and remainingTarget is the portion of the target unhandled by the tree
			// If there are no keys in remainingTarget, then there's no need for a target here
			var remainingTargetHasKeys = Object.keys(remainingTarget).length > 0;

			// If there are any permissions at this level of the tree that have the same target, combine the respective grants
			var grantWasCombined = false;
			for(i = 0; i < curTree.perms.length; i++) {
				if((!curTree.perms[i].target && !remainingTargetHasKeys) || JSON.stringify(curTree.perms[i].target || null) == JSON.stringify(remainingTarget)) {
					curTree.perms[i].grant = Grant.combineGrants(curTree.perms[i].grant, grant);
					grantWasCombined = true;
					break;
				}
			}

			// If we didn't find an existing permission to add this grant to, add a new one
			if(!grantWasCombined) {
				curTree.perms.push({
					target: remainingTargetHasKeys ? remainingTarget : undefined,
					grant: grant
				});
			}
		}

		// Loop through all of the permissions, recursively combining child permissions, and adding each to the tree
		function addAllPermissions(permArray, baseTarget) {
			var i;
			for(i = 0; i < permArray.length; i++) {
				var perm = permArray[i];
				var target = perm.target;
				if(typeof target == 'string' && target[0] == '{') {
					try {
						target = JSON.parse(target);
					} catch(ex) {}
				}
				if(target && typeof target == 'object') {
					commonQuery.substituteVars(target, permissionVars || {}, true);
				}
				var grant = Grant.grantNumbersToObjects(perm.grant);
				if(baseTarget) {
					target = combineTargetQueries(target || {}, baseTarget);
				}
				addPermissionToTree(target, grant);
				if(Array.isArray(perm.children)) {
					addAllPermissions(perm.children, target);
				}
			}
		}
		addAllPermissions(permArray);

		return tree;

	}

	for(targetType in permissionsByTargetType) {
		permissionsByTargetType[targetType] = buildTargetTypeTree(permissionsByTargetType[targetType]);
	}

	return permissionsByTargetType;
}

// Combines 2 queries, trying to maintain as many matches at the root level as possible
function combineTargetQueries() {
	if(!arguments.length) return false;
	if(arguments.length == 1) return arguments[0];
	var resultQuery = {};
	var andClauses = [];
	var key;
	for(var queryNum = 0; queryNum < arguments.length; queryNum++) {
		var curQuery = arguments[queryNum];
		if(!curQuery || typeof curQuery != 'object') {
			curQuery = {};
		}
		for(key in curQuery) {
			if(key == '$and') {
				if(Array.isArray(curQuery.$and)) {
					Array.prototype.push.apply(andClauses, curQuery.$and);
				}
			} else if(resultQuery[key] === undefined) {
				resultQuery[key] = curQuery[key];
			} else {
				var oldKeyQuery = {}, curKeyQuery = {};
				oldKeyQuery[key] = resultQuery[key];
				curKeyQuery[key] = curQuery[key];
				andClauses.push(oldKeyQuery, curKeyQuery);
				delete resultQuery[key];
			}
		}
	}
	if(andClauses.length) {
		resultQuery.$and = andClauses;
	}
	return resultQuery;
}

},{"./grant":1,"blueimp-md5":"blueimp-md5","common-query":"common-query","objtools":"objtools","zs-error":"zs-error"}],"zs-permission":[function(_dereq_,module,exports){
module.exports = _dereq_('./permission-set');

},{"./permission-set":2}]},{},[])("zs-permission")
});