angular.module('mnServers')
  .controller('mnServersListItemDetailsController',
    function ($scope, mnServersListItemDetailsService) {
      $scope.$watch('node', function () {
        mnServersListItemDetailsService.getNodeDetails($scope.node).then(function (details) {
          $scope.server = details;
        });
      });
    });