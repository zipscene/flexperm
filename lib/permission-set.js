// Copyright 2016 Zipscene, LLC
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

const createQuery = require('common-query').createQuery;
const objtools = require('objtools');
const Grant = require('./grant');
const XError = require('xerror');


/**
 * Encapsulate a plain permission array and turns it into a usable object.
 *
 * A permission array ties an API user to a set of actions they are authorized to perform. The data format is
 * an array of objects, eacn of which has three keys:
 *
 *   - target: A string denoting the type of object or procedure this permissions grants access to. By convention,
 *       a lower camel case target refers to a group of procedures, while upper camel case refers to object access.
 *   - match: A query object. This is used to determine which objects a user has access to. When the PermissionSet is
 *       used for procesure access, this is a used to query against a 'virtual' object - see below for an example.
 *   - grant: An object denoting the set of authorized operations a user has against a matched object.
 *
 * An example of the declaration and usage of permissions follows:
 *
 *   ```javascript
 *   // An brand admin will have access to view, cancel, and void any or to his brand
 *   var permArray = [ {
 *     target: 'ordering',
 *     match: {
 *       brandId: 'zcafe'
 *     },
 *     grant: {
 *       get: true,
 *       cancel: true,
 *       void: true
 *     }
 *   } ];
 *   var permSet = new PermissionSet(permArray);
 *   // Is user authorized to void a specific order?
 *   var orderPermissionData = { brandId: 'zcafe', orderId: 'abc123' };
 *   permSet.getTargetGrant('ordering', orderPermissionData).check('void'); // returns true
 *   // Is user authorized to submit a specific order?
 *   permSet.getTargetGrant('ordering', orderPermissionData).check('submit'); // throws XError
 *   // Is user authorized to submit an order for a different brand?
 *   orderPermissionData.brandId = 'billy-bobs-burger-bayou';
 *   permSet.getTargetGrant('ordering', orderPermissionData).check('void'); // throws XError
 *   ```
 *
 * @class PermissionSet
 * @constructor
 * @param {Object[]} permArray - The permission array that this PermissionSet will handle.
 * @param {Object} [permissionVars] - Map of variable names to values. These will be subsituted in for
 *   any $var statements in the permission match objects.
 * @param {Boolean} [_empty] - Returns an empty PermissionSet object. Intended for internal use only.
 */
class PermissionSet {

	constructor(permArray, permissionVars, _empty) {
		if (_empty) return;
		this._array = permArray;
		this._vars = permissionVars;
		this._hashCache = {};	// cache of hashes by target
		this.rebuild();
	}

	/**
	 * Reconstructs the internal data structures used for permission processing. Call this if the permission
	 * array is externally modified after the PermissionSet is instantiated.
	 *
	 * @method rebuild
	 */
	rebuild() {
		this._tree = this.buildPermissionTree(this._array, this._vars);
		this._hashCache = {};
		// Precompute hashes
		for (let target in this._tree) {
			this.getHash(target);
		}
	}

	/**
	 * Constructs a PermissionSet object from a legacy, zsapi1-style permission array. The only changes were
	 * renaming target -> match and targetType -> target. Throws if input array is not actually an array.
	 *
	 * @method fromLegacyPermissions
	 * @static
	 * @throws XError
	 * @param {Object[]} legacyArray - Array of legacy permission objects.
	 * @return {PermissionSet}
	 */
	static fromLegacyPermissions(legacyArray) {
		if (!Array.isArray(legacyArray)) {
			throw new XError(XError.INTERNAL_ERROR, 'Legacy permission array parameter is not an array');
		}
		legacyArray = objtools.deepCopy(legacyArray);
		let permissionArray = [];
		for (let legacyPermission of legacyArray) {
			if (!legacyPermission) continue;
			if (legacyPermission.target) {
				legacyPermission.match = legacyPermission.target;
				delete legacyPermission.target;
			}
			if (legacyPermission.targetType) {
				legacyPermission.target = legacyPermission.targetType;
				delete legacyPermission.targetType;
			}
			permissionArray.push(legacyPermission);
		}
		return new PermissionSet(permissionArray);
	}

	/**
	 * Constructs and returns a Grant object representing the authorization this PermissionSet gives for a
	 * specific target and match object. The Grant object contains specific information on what methods are
	 * allowed.
	 *
	 * @method getTargetGrant
	 * @param {String} target - The target string.
	 * @param {Object} match - The match query object.
	 * @return {Grant}
	 */
	getTargetGrant(target, match) {
		let tree = this._tree[target];
		let wildcardTree = this._tree['*'];
		let grantObjects = [];
		if (tree) Array.prototype.push.apply(grantObjects, this.getPermissionTreeMatchingGrants(tree, match));
		if (wildcardTree) {
			Array.prototype.push.apply(grantObjects, this.getPermissionTreeMatchingGrants(wildcardTree, match));
		}
		if (!grantObjects.length) return new Grant(false, target, match);
		if (grantObjects.length === 1) return new Grant(grantObjects[0], target, match);
		return new Grant(Grant.combineGrants.apply(null, grantObjects), target, match);
	}

	/**
	 * Returns the raw permission array used by this PermissionSet. If this array is modified, call rebuild() to
	 * see the PermissionSet reflect the changes.
	 *
	 * @method asArray
	 * @return {Object[]}
	 */
	asArray() {
		return this._array;
	}

	toJSON() {
		return this._array;
	}

	/**
	 * Get a list of all fields used by the match query objects for a given target. This represents the 'important'
	 * fields that are significant in permission checking.
	 *
	 * @method getTargetQueryFields
	 * @param {String} target - The target string.
	 * @return {String[]} - Array of field names.
	 */
	getTargetQueryFields(target) {
		let tree = this._tree[target];
		let wildcardTree = this._tree['*'];
		let fieldSet = {};
		if (tree) this.getPermissionTreeQueryFields(tree, target, fieldSet);
		if (wildcardTree) this.getPermissionTreeQueryFields(wildcardTree, target, fieldSet);
		return Object.keys(fieldSet);
	}

	/**
	 * Get a hash of the permission data for a given target. Two PermissionSets from identical
	 * permission arrays will yield identical hashes.
	 *
	 * @method getHash
	 * @param {String} target - The target string.
	 * @return {String} - The hash string.
	 */
	getHash(target) {
		let targetStr = target ? target : '___';
		if (this._hashCache[targetStr]) return this._hashCache[targetStr];
		let array = this.asArray();
		if (target) {
			array = array.filter(function(p) {
				return p.target === target;
			});
			if (!array.length) return 'xxxxxxxx';
		}
		let hash = objtools.objectHash(array);
		this._hashCache[targetStr] = hash;
		return hash;
	}

	/**
	 * Constructs a function that will filter an object; for example, when using a readMask for object access.
	 * This function will filter an input object to the subset of it a user is authorized to view or edit.
	 * It will ensure that the user is authorized to perform the action specified by grantPath (e.g. 'read').
	 *
	 * @method createFilterByMask
	 * @param {String} target - The target string.
	 * @param {String} grantPath - The path in the grant that the user must have authorization for to read
	 *   anything at all.
	 * @param {String} maskName - The grant property name of the mask to filter by.
	 * @return {Function} Accepts input objects as its only parameters. This function will return a filtered
	 *   object, or null, if the user is not authorized to access the object at all.
	 */
	createFilterByMask(target, grantPath, maskName) {
		return (obj) => {
			let grant = this.getTargetGrant(target, obj || {});
			if (!grant.has(grantPath)) return null;
			let mask = grant.getMask(maskName);
			mask = new objtools.ObjectMask(mask);
			return mask.filterObject(obj);
		};
	}

	/**
	 * Checks whether the given query can be executed on an object of the given target. This amounts to
	 * ensuring that user can read and query the target, and all query fields are contained in the
	 * permission readMask. Authorization failure errors will be thrown.
	 *
	 * @method checkExecuteQuery
	 * @throws XError
	 * @param {String} target - The target string.
	 * @param {Mixed} query - A CommonQuery, or a plain object in CommonQuery form.
	 * @param {Object} [queryOptions]
	 * @param {String[]} [queryOptions.fields] - Array of fields the user has requested to be returned.
	 * @param {String[]} [queryOptions.sort] - Array of fields the user has requested to sort by.
	 * @param {Number} [queryOptions.limit] - The user-requested limit of objects to be returned.
	 * @param {String} [queryTypeGrantName] - Supply this to check for a permission on the grant
	 *   other than 'read' and 'query' (e.g. 'count').
	 * @return {Boolean} - Boolean true on success.
	 */
	checkExecuteQuery(target, query, queryOptions, queryTypeGrantName) {
		let cQuery;
		if (typeof query.getExactMatches === 'function') {
			cQuery = query;
		} else {
			cQuery = createQuery(query);
		}

		// get the query grant for this query
		let queryGrant = this.getTargetGrant(target, cQuery.getExactMatches().exactMatches);

		// Make sure the user has read or query permission for the query
		if (queryTypeGrantName) {
			if (!Array.isArray(queryTypeGrantName)) queryTypeGrantName = [ queryTypeGrantName ];
			for (let grantName of queryTypeGrantName) {
				queryGrant.check(grantName);
			}
		} else {
			queryGrant.check('read');
			queryGrant.check('query');
		}

		// Make sure the user can read all fields used in the query
		queryGrant.check(cQuery.getQueriedFields(), 'readMask.');

		// Make sure the user can read or query on all sort fields
		if (queryOptions && queryOptions.sort) {
			if (!Array.isArray(queryOptions.sort)) {
				throw new XError(XError.BAD_REQUEST,
					'Permission-Set checkExecuteQuery got badly formatted sort option',
					{ sort: queryOptions.sort }
				);
			}
			queryGrant.check(queryOptions.sort.map(function(f) {
				if (typeof f !== 'string') return '';
				if (f[0] === '-' || f[0] === '+') return f.slice(1);
				else return f;
			}), 'readMask.');
		}

		// Make sure the requested limit is within the user's maximum
		let maxLimit = queryGrant.max('maxQueryLimit');
		if (
			maxLimit !== null && maxLimit !== undefined && maxLimit !== Infinity &&
			queryOptions && typeof queryOptions.limit === 'number'
		) {
			if (queryOptions.limit > maxLimit) {
				throw new XError(XError.ACCESS_DENIED,
					`The requested limit of ${queryOptions.limit} is above your maximum allowed of ` +
						`${maxLimit} for type ${target}`
				);
			}
		}

		return true;
	}

	/**
	 * Serialize this PermissionSet's internal data. This can be passed to the static method deserialize()
	 * to more quickly reconstruct a PermissionSet.
	 *
	 * @method serialize
	 * @return {Object} - Object containing serialized data.
	 */
	serialize() {
		return {
			_array: this._array,
			_vars: this._vars,
			_tree: this._tree,
			_hashCache: this._hashCache
		};
	}

	/**
	 * Construct a PermissionSet from serialized data.
	 *
	 * @method deserialize
	 * @static
	 * @param {Object} ser - The return value of another PermissionSet's serialize().
	 * @return {PermissionSet}
	 */
	static deserialize(ser) {
		let p = new PermissionSet(null, null, true);
		p._array = ser._array;
		p._vars = ser._vars;
		p._tree = ser._tree;
		p._hashCache = ser._hashCache;
		return p;
	}

	/* Given a permission tree object and match object, return an array of grants that are
	 * match by the match object.
	 *
	 * @method getPermissionTreeMatchingGrants
	 * @private
	 */
	getPermissionTreeMatchingGrants(permTree, matchObject) {
		let grants = [];
		function addMatchingGrants(tree) {
			let i, j;
			for (i = 0; i < tree.perms.length; i++) {
				let perm = tree.perms[i];
				if (!perm.remainingMatch || createQuery(perm.remainingMatch).matches(matchObject)) {
					grants.push(tree.perms[i].grant);
				}
			}
			for (i = 0; i < tree.matches.length; i++) {
				let match = tree.matches[i];
				let objFieldValue = objtools.getPath(matchObject, match.field);
				if (objFieldValue !== undefined) {
					let subtree;
					if (Array.isArray(objFieldValue)) {
						for (j = 0; j < objFieldValue.length; j++) {
							subtree = match.values[objFieldValue[j]];
							if (subtree) {
								addMatchingGrants(subtree);
							}
						}
					} else {
						subtree = match.values[objFieldValue];
						if (subtree) {
							addMatchingGrants(subtree);
						}
					}
				}
			}
		}
		addMatchingGrants(permTree);
		return grants;
	}

	/**
	 * Get the set of match fields used by a permission tree for a given target. Appends the results
	 * to fieldSet.
	 *
	 * @method getPermissionTreeQuery
	 * @param {Object} permTree
	 * @param {Mixed} target
	 * @param {Object} fieldSet
	 * @private
	 */
	getPermissionTreeQueryFields(permTree, target, fieldSet) {
		function addBranch(tree) {
			let i, j, queryFields;
			// Add fields used by remaining target queries
			if (tree.perms) {
				for (i = 0; i < tree.perms.length; i++) {
					if (tree.perms[i].remainingMatch) {
						queryFields = createQuery(tree.perms[i].remainingMatch).getQueriedFields();
						for (j = 0; j < queryFields.length; j++) {
							fieldSet[queryFields[j]] = true;
						}
					}
				}
			}
			// Add fields used by each match, and recurse
			if (tree.matches) {
				for (i = 0; i < tree.matches.length; i++) {
					let match = tree.matches[i];
					fieldSet[match.field] = true;
					if (match.values) {
						for (let val in match.values) {
							let subtree = match.values[val];
							addBranch(subtree);
						}
					}
				}
			}
		}
		addBranch(permTree);
	}

	/**
	 * Construct a permission tree from an input permission array and set of permission variables.
	 * This will substitute $vars variables and will also convert grant number
	 * to grant object both in the constructed tree and the passed in `permArray`
	 *
	 * For efficient lookups, we build a tree of targets out of the permission array.
	 * It can only build this tree for for portions of queries which are AND'd exact matches.
	 * The tree will look like this:
	 * {
	 * 	User: {
	 *		perms: [ ... ],
	 *		matches: [
	 *			{
	 *				field: 'ns',
	 *				values: {
	 *					'zs': {
	 *						perms: [ ... ],
	 *						matches: [ ... ]
	 *					}
	 *				}
	 *			}
	 *		]
	 *
	 * @method buildPermissionTree
	 * @private
	 * @param {Array} permArray
	 * @param {Mixed} permissionVars
	 * @return {Object}
	 */
	buildPermissionTree(permArray, permissionVars) {
		// We will treat each target type separately.  Construct a map from target types to the contained permissions.
		let permissionsByTarget = {};
		for (let perm of permArray) {
			if (perm.type === 'target' || !perm.type) {
				if (perm.target) {
					if (permissionsByTarget[perm.target]) {
						permissionsByTarget[perm.target].push(perm);
					} else {
						permissionsByTarget[perm.target] = [ perm ];
					}
				}
			}
		}

		// Build up a tree for each target type
		function buildTargetTree(permArray) {

			// When building the tree, we want to have to iterate through as few fields at each node as possible.
			// Calculate which fields are matched on, and sort by number of occurrences
			// in the permission array (greatest to least)
			let numMatchesByField = {};
			function addPermissionsMatches(permArray) {
				for (let perm of permArray) {
					if (perm.match && typeof perm.match === 'object') {
						for (let field in perm.match) {
							if (typeof field !== 'object' && field[0] !== '$') {
								numMatchesByField[field] = (numMatchesByField[field] || 0) + 1;
							}
						}
					}
				}
			}
			addPermissionsMatches(permArray);
			let fieldOrder = [];
			for (let field in numMatchesByField) {
				fieldOrder.push(field);
			}
			fieldOrder.sort(function(a, b) {
				return numMatchesByField[b] - numMatchesByField[a];
			});
			// fieldOrder now contains the fields that we will check, in order from most matches to least matches

			let tree = {
				perms: [],
				matches: []
			};

			function addPermissionToTree(match, grant) {
				// keep track of the "remaining" fields in the match not addressed by the tree
				let remainingMatch = {};
				for (let field in match) {
					remainingMatch[field] = match[field];
				}

				// traverse the tree in order of the fields to find where to insert this permission
				// this is a pointer to the current tree node
				let curTree = tree;
				for (let i = 0; i < fieldOrder.length; i++) {

					// Get the field name and value from its position in the ordered field list
					let field = fieldOrder[i];
					let fieldValue = remainingMatch[field];

					// If the field is not matched, or is not a simple scalar match, move on to the next field
					if (fieldValue === undefined || typeof fieldValue === 'object') {
						continue;
					}

					// Find or create the match that corresponds to this field
					let curMatch = null;
					for (let j = 0; j < curTree.matches.length; j++) {
						if (curTree.matches[j].field === field) {
							curMatch = curTree.matches[j];
						}
					}
					if (!curMatch) {
						curMatch = {
							field,
							values: {}
						};
						curTree.matches.push(curMatch);
					}

					// If the value of this match already exists, use that as the next curTree.  Otherwise create one.
					if (curMatch.values[fieldValue]) {
						curTree = curMatch.values[fieldValue];
					} else {
						curTree = {
							perms: [],
							matches: []
						};
						curMatch.values[fieldValue] = curTree;
					}

					// Since this field match is now handled by the tree, remove it from the remaining match
					delete remainingMatch[field];
				}

				// curTree now points to the part of the tree where the permission should be added,
				// and remainingMatch is the portion of the match unhandled by the tree
				// If there are no keys in remainingMatch, then there's no need for a match here
				let remainingMatchHasKeys = Object.keys(remainingMatch).length > 0;

				// If there are any permissions at this level of the tree that have the same target,
				// combine the respective grants
				let grantWasCombined = false;
				for (let i = 0; i < curTree.perms.length; i++) {
					if (
						(!curTree.perms[i].match && !remainingMatchHasKeys) ||
							JSON.stringify(curTree.perms[i].match || null) ===
						JSON.stringify(remainingMatch)
					) {
						curTree.perms[i].grant = Grant.combineGrants(curTree.perms[i].grant, grant);
						grantWasCombined = true;
						break;
					}
				}

				// If we didn't find an existing permission to add this grant to, add a new one
				if (!grantWasCombined) {
					curTree.perms.push({
						remainingMatch: remainingMatchHasKeys ? remainingMatch : undefined,
						grant
					});
				}
			}

			// Loop through all of the permissions, adding each to the tree
			function addAllPermissions(permArray) {
				for (let perm of permArray) {
					let match = perm.match;
					if (typeof match === 'string' && match[0] === '{') {
						try {
							match = JSON.parse(match);
						} catch (ex) { /* Discard */ }
					}
					if (match && typeof match === 'object') {
						let cQuery = createQuery(match, {
							vars: permissionVars || {}
						});
						perm.match = cQuery.getData();
					}
					perm.grant = Grant.grantNumbersToObjects(perm.grant);
					addPermissionToTree(perm.match, perm.grant);
				}
			}

			addAllPermissions(permArray);
			return tree;

		}

		for (let target in permissionsByTarget) {
			permissionsByTarget[target] = buildTargetTree(permissionsByTarget[target]);
		}

		return permissionsByTarget;
	}

}

PermissionSet.Grant = Grant;

module.exports = PermissionSet;
