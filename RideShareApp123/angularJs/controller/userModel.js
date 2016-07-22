var app = angular.module('myApp', []);
app.controller('userModel', ['$scope', function ($scope) {
		$scope.firstName = "John";
		$scope.lastName = "Doe";
	}]);
