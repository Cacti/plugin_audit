<?php

use PHPUnit\Framework\TestCase;

final class AuditFunctionsTest extends TestCase {
    protected function setUp(): void {
        parent::setUp();

        $_REQUEST = [];
        $_SERVER = [];
        $_SESSION = [];
    }

    public function testBuildsPageQueryMapWithExpectedKeys(): void {
        $map = auditBuildPageQueryMap();

        $this->assertArrayHasKey('host.php', $map);
        $this->assertArrayHasKey('automation_devices.php', $map);
        $this->assertStringContainsString('FROM host', $map['host.php']);
    }

    public function testTransformsAutomationFieldsToReadableLabels(): void {
        $rows = [
            ['snmp' => 1, 'up' => 0],
            ['snmp' => 0, 'up' => 1],
        ];

        $out = auditTransformAutomationDevices($rows);

        $this->assertSame('UP', $out[0]['snmp']);
        $this->assertSame('No', $out[0]['up']);
        $this->assertSame('Down', $out[1]['snmp']);
        $this->assertSame('Yes', $out[1]['up']);
    }

    public function testReturnsEmptySelectionDefaultsWhenSelectedItemsMissing(): void {
        [$items, $dropAction] = auditGetSelectedItemsData(['foo' => 'bar']);

        $this->assertSame([], $items);
        $this->assertFalse($dropAction);
    }

    public function testParsesSelectedItemsAndDropActionFromPayload(): void {
        $post = [
            'selected_items' => addslashes(serialize([101, 202])),
            'drp_action' => 4,
        ];

        [$items, $dropAction] = auditGetSelectedItemsData($post);

        $this->assertSame([101, 202], $items);
        $this->assertSame(4, $dropAction);
    }

    public function testResolvesBasePathFromConfigWhenCactiPathBaseIsNotDefined(): void {
        $config = ['base_path' => '/tmp/cacti'];

        $this->assertSame('/tmp/cacti', auditGetBasePath($config));
    }

    public function testMapsKnownActionLabelsAndFallsBackForUnknownPages(): void {
        $this->assertSame('Delete Device', auditResolveAction('automation_devices.php', 2, 'fallback'));
        $this->assertSame('Host Disabled', auditResolveAction('host.php', 3, 'fallback'));
        $this->assertSame('fallback', auditResolveAction('unknown.php', 1, 'fallback'));
    }

    public function testSanitizesPostPayloadAndInfersDeleteAction(): void {
        $_REQUEST = [
            '__csrf_magic' => 'token',
            'header' => 'header',
            'db_pass' => 'secret',
            'foo' => 'bar',
            'drp_action' => 1,
        ];

        $action = '';
        $post = auditPrepareRequestPost($action);

        $this->assertSame('delete', $action);
        $this->assertArrayNotHasKey('__csrf_magic', $post);
        $this->assertArrayNotHasKey('header', $post);
        $this->assertArrayNotHasKey('db_pass', $post);
        $this->assertSame('bar', $post['foo']);
    }

    public function testBuildsGuiEventDataWithoutTouchingDatabaseWhenNoSelectedItems(): void {
        $_REQUEST = [
            'foo' => 'bar',
            'action' => 'save',
        ];
        $_SERVER['SCRIPT_NAME'] = '/var/www/html/data_sources.php';
        $_SERVER['HTTP_USER_AGENT'] = 'UnitTestAgent';
        $_SESSION = [];

        $action = '';
        $config = ['base_path' => '/tmp/cacti'];

        $event = auditBuildGuiEventData($config, $action);

        $this->assertSame('data_sources.php', $event['page']);
        $this->assertSame(0, $event['user_id']);
        $this->assertSame('save', $event['action']);
        $this->assertSame('127.0.0.1', $event['ip_address']);
        $this->assertSame('UnitTestAgent', $event['user_agent']);
        $this->assertSame('[]', $event['object_data']);
        $this->assertSame('/tmp/cacti', $event['base_path']);
    }
}
