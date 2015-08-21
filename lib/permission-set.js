var Query = require('zs-common-query').Query;
var objtools = require('zs-objtools');
var Grant = require('./grant');
var md5 = require('blueimp-md5');
var XError = require('xerror');

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
// Returns null on success or XError on error
PermissionSet.prototype.checkExecuteQuery = function(targetType, query, queryOptions, queryTypeGrantName) {
	var cQuery = new Query(query);

	// get the query grant for this query
	var queryGrant = this.getTargetGrant(targetType, cQuery.getExactMatches());

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
	accessError = queryGrant.check(cQuery.getFields(), 'readMask.');
	if(accessError) return accessError;

	// Make sure the user can read all fields requested to be returned (not strictly necessary, but will generate helpful errors early)
	if(queryOptions && queryOptions.fields) {
		if(!Array.isArray(queryOptions.fields)) return new XError(XError.BAD_REQUEST, 'Permission-Set checkExecuteQuery got badly formatted fields option', { fields: queryOptions.fields });
		accessError = queryGrant.check(queryOptions.fields, 'readMask.');
		if(accessError) return accessError;
	}

	// Make sure the user can read or query on all sort fields
	if(queryOptions && queryOptions.sort) {
		if(!Array.isArray(queryOptions.sort)) return new XError(XError.BAD_REQUEST, 'Permission-Set checkExecuteQuery got badly formatted sort option', { sort: queryOptions.sort });
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
			return new XError(XError.ACCESS_DENIED, 'The requested limit of ' + queryOptions.limit + ' is above your maximum allowed of ' + maxLimit + ' for type ' + targetType);
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
			if(!perm.target || new Query(perm.target).matches(targetObject)) {
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
					queryFields = new Query(tree.perms[i].target).getFields();
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
					var cQuery = new Query(target);
					cQuery.substituteVars(target, permissionVars || {}, true);
					target = cQuery.toObject();
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
