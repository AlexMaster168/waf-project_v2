from rest_framework import serializers
from waf_core.models import (
    AttackType, HTTPRequest, DetectedAttack,
    FirewallException, Alert, WAFRule, IPReputation, MLModelMetrics,
)


class AttackTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackType
        fields = '__all__'


class HTTPRequestSerializer(serializers.ModelSerializer):
    attacks_count = serializers.SerializerMethodField()

    class Meta:
        model = HTTPRequest
        fields = '__all__'

    def get_attacks_count(self, obj):
        return obj.attacks.count()


class DetectedAttackSerializer(serializers.ModelSerializer):
    attack_type = AttackTypeSerializer(read_only=True)
    request_path = serializers.CharField(source='request.path', read_only=True)
    client_ip = serializers.CharField(source='request.client_ip', read_only=True)

    class Meta:
        model = DetectedAttack
        fields = '__all__'


class FirewallExceptionSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    is_expired = serializers.SerializerMethodField()

    class Meta:
        model = FirewallException
        fields = '__all__'
        read_only_fields = ['hit_count', 'created_at', 'updated_at']

    def get_is_expired(self, obj):
        return obj.is_expired()


class AlertSerializer(serializers.ModelSerializer):
    attack_type = AttackTypeSerializer(read_only=True)
    acknowledged_by_name = serializers.CharField(source='acknowledged_by.username', read_only=True)

    class Meta:
        model = Alert
        fields = '__all__'
        read_only_fields = ['created_at', 'email_sent']


class WAFRuleSerializer(serializers.ModelSerializer):
    attack_type = AttackTypeSerializer(read_only=True)
    attack_type_id = serializers.PrimaryKeyRelatedField(
        queryset=AttackType.objects.all(), source='attack_type',
        write_only=True, required=False,
    )

    class Meta:
        model = WAFRule
        fields = '__all__'


class IPReputationSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPReputation
        fields = '__all__'


class MLModelMetricsSerializer(serializers.ModelSerializer):
    class Meta:
        model = MLModelMetrics
        fields = '__all__'
