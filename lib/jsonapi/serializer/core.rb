# frozen_string_literal: true

require 'digest/sha1'

module JSONAPI
  module Serializer
    # Our JSONAPI implementation
    module Core
      DEFAULT_CACHE_NAMESPACE = 'jsonapi-serializer'

      def record_hash(record, fieldset, params)
        if @cache_store_instance
          cache_opts = record_cache_options(
            @cache_store_options, fieldset, @options
          )

          rhash = @cache_store_instance.fetch(record, **cache_opts) do
            temp_hash = id_hash(
              id_from_record(record, params),
              use_default: true
            )

            if @attributes_to_serialize
              temp_hash[:attributes] = attributes_hash(record, fieldset, params)
            end

            temp_hash[:relationships] = relationships_hash(
              record,
              cachable_relationships_to_serialize,
              fieldset,
              params
            ) unless cachable_relationships_to_serialize.nil?

            temp_hash[:links] = links_hash(record, params) if @data_links
            temp_hash
          end
          rhash[:relationships] = (rhash[:relationships] || {}).merge(
            relationships_hash(
              record,
              uncachable_relationships_to_serialize,
              fieldset,
              params
            )
          ) unless uncachable_relationships_to_serialize.nil?
        else
          rhash = id_hash(id_from_record(record, params), use_default: true)

          if @attributes_to_serialize
            rhash[:attributes] = attributes_hash(record, fieldset, params)
          end

          if @relationships_to_serialize
            rhash[:relationships] = relationships_hash(
              record,
              @relationships_to_serialize,
              fieldset,
              params
            )
          end

          rhash[:links] = links_hash(record, params) if @data_links
        end

        if @meta_to_serialize
          rhash[:meta] = call_proc(@meta_to_serialize, record, params)
        end

        rhash
      end

      def record_includes(record, items, known, fieldsets, params)
        return [] if items.nil? || @relationships_to_serialize.nil?
        return [] if items.empty? || @relationships_to_serialize.empty?

        items = parse_includes_list(items)

        items.each_with_object([]) do |(item, item_includes), included|
          rel = @relationships_to_serialize[item]

          raise IncludeError.new(item, self) if rel.nil?

          rel_options = rel[:options]

          next unless condition_passes?(rel_options[:if], record, params)

          rel_objects = call_proc_or_method(
            rel[:object_block] || rel[:name], record, params
          )

          next if rel_objects.nil? ||
            (rel_objects.respond_to?(:empty?) && rel_objects.empty?)

          serializer = rel_options[:serializer]

          Array(rel_objects).each do |rel_obj|
            if serializer.is_a?(Proc)
              serializer = call_proc(serializer, rel_obj, params)
            end

            item_serializer = serializer
            item_serializer ||= ::JSONAPI::Serializer.for_object(
              rel_obj, rel_options[:serializers]
            )

            if item_includes.any?
              included.concat(
                item_serializer.record_includes(
                  rel_obj, item_includes, known, fieldsets, params
                )
              )
            end

            rel_obj_id = item_serializer.record_type.to_s.dup.concat(
              item_serializer.id_from_record(rel_obj, params).to_s
            )

            next if known.include?(rel_obj_id)

            known << rel_obj_id

            included << item_serializer.record_hash(
              rel_obj, fieldsets[item_serializer.record_type], params
            )
          end
        end
      end

      def id_from_record(record, params)
        raise ::JSONAPI::Serializer::IdError if record_id.nil?

        call_proc_or_method(record_id, record, params)
      end

      def id_hash(id, use_default: false)
        if id.present?
          { id: id.to_s, type: record_type }
        elsif use_default
          { id: nil, type: record_type }
        end
      end

      private

      def relationships_hash(record, relationships, fieldset, params)
        relationships = relationships.slice(*fieldset) unless fieldset.nil?

        relationships.each_with_object({}) do |(key, rel), rhash|
          rel_opts = rel[:options]

          next unless condition_passes?(rel_opts[:if], record, params)

          key = run_key_transform(key)

          rhash[key] = {}
          rhash[key][:data] = relationship_ids(rel, record, params)

          if rel_opts[:meta].is_a?(Proc)
            rhash[key][:meta] = call_proc(rel_opts[:meta], record, params)
          elsif rel_opts[:meta].is_a?(Hash)
            rhash[key][:meta] = rel_opts[:meta]
          end

          if rel_opts[:links].is_a?(Hash)
            rhash[key][:links] = \
              rel_opts[:links].each_with_object({}) do |(lkey, lmethod), lhash|
                lkey = run_key_transform(lkey)
                lhash[lkey] = call_proc_or_method(lmethod, record, params)
              end
          elsif !rel_opts[:links].to_s.empty?
            rhash[key][:links] = record.public_send(rel_opts[:links])
          end
        end
      end

      def relationship_ids(relationship, record, params)
        rel_opts = relationship[:options]
        has_many = (relationship[:relationship_type] == :has_many)
        serializer = rel_opts[:serializer]

        ids_rails_postfix = '_id'
        ids_rails_postfix = '_ids' if has_many

        if serializer.is_a?(Class)
          ids_meth = rel_opts[:ids_method_name]
          ids_meth ||= relationship[:name].to_s + ids_rails_postfix

          ids = record.public_send(ids_meth) if record.respond_to?(ids_meth)

          return serializer.id_hash(ids) unless ids.nil? && has_many

          return ids.map! { |oid| serializer.id_hash(oid) } unless ids.nil?
        end

        obj_method_name = relationship[:object_block] || relationship[:name]
        rel_objects = call_proc_or_method(obj_method_name, record, params)
        rel_objects = Array(rel_objects)
        ids = rel_objects.map do |robj|
          robj_ser = serializer

          robj_ser = call_proc(robj_ser, robj, params) if robj_ser.is_a?(Proc)

          robj_ser ||= ::JSONAPI::Serializer.for_object(robj)
          robj_ser.id_hash(robj_ser.id_from_record(robj, params))
        end

        return ids if has_many

        ids.first
      end

      def cachable_relationships_to_serialize
        return nil if @relationships_to_serialize.nil?

        @cachable_relationships_to_serialize ||= (
          @relationships_to_serialize.to_a -
            uncachable_relationships_to_serialize.to_a
        ).to_h
      end

      def uncachable_relationships_to_serialize
        return nil if @relationships_to_serialize.nil?

        @uncachable_relationships_to_serialize ||= \
          @relationships_to_serialize.select do |_, rel|
            rel[:options][:serializer]&.cache_store_instance.nil?
          end
      end

      def links_hash(record, params = {})
        @data_links.each_with_object({}) do |(key, link), lhash|
          options = link[:options]
          method = link[:method]

          next unless condition_passes?(options[:if], record, params)

          key = run_key_transform(key)

          lhash[key] = call_proc_or_method(method, record, params)
        end
      end

      # Cache options helper. Use it to adapt cache keys/rules.
      #
      # If a fieldset is specified, it modifies the namespace to include the
      # fields from the fieldset.
      #
      # @param options [Hash] default cache options
      # @param fieldset [Array, nil] passed fieldset values
      # @param params [Hash] the serializer params
      #
      # @return [Hash] processed options hash
      # rubocop:disable Lint/UnusedMethodArgument
      def record_cache_options(options, fieldset, params)
        return options unless fieldset

        options = options ? options.dup : {}
        options[:namespace] ||= const_get('DEFAULT_CACHE_NAMESPACE')

        fskey = fieldset.join('_')

        # Use a fixed-length fieldset key if the current length is more than
        # the length of a SHA1 digest
        fskey = Digest::SHA1.hexdigest(fskey) if fskey.length > 40

        options[:namespace] = "#{options[:namespace]}-fieldset:#{fskey}"
        options
      end
      # rubocop:enable Lint/UnusedMethodArgument

      def attributes_hash(record, fieldset, params)
        attributes = @attributes_to_serialize
        attributes = attributes.slice(*fieldset) unless fieldset.nil?

        attributes.each_with_object({}) do |(key, attribute), ahash|
          options = attribute[:options] || {}
          method = attribute[:method]

          next unless condition_passes?(options[:if], record, params)

          key = run_key_transform(key)

          ahash[key] = call_proc_or_method(method, record, params)
        end
      end

      def condition_passes?(maybe_proc, record, params)
        return true unless maybe_proc.is_a?(Proc)

        call_proc(maybe_proc, record, params)
      end

      def call_proc_or_method(maybe_proc, record, params)
        return call_proc(maybe_proc, record, params) if maybe_proc.is_a?(Proc)

        record.public_send(maybe_proc)
      end

      # Calls [Proc] with respect to the number of parameters it takes
      #
      # @param proc [Proc] to call
      # @param params [Array] of parameters to be passed to the Proc
      # @return [Object] the result of the Proc call with the supplied parameters
      def call_proc(proc, *params)
        proc.call(*params.take(proc.parameters.length))
      end

      # It chops out the root association (first part) from each include.
      #
      # It keeps an unique list and collects all of the rest of the include
      # value to hand it off to the next related to include serializer.
      #
      # This method will turn that include array into a Hash that looks like:
      #
      #   {
      #       authors: Set.new([
      #         'books',
      #         'books.genre',
      #         'books.genre.books',
      #         'books.genre.books.authors',
      #         'books.genre.books.genre'
      #       ]),
      #       genre: Set.new(['books'])
      #   }
      #
      # Because the serializer only cares about the root associations
      # included, it only needs the first segment of each include
      # (for books, it's the "authors" and "genre") and it doesn't need to
      # waste cycles parsing the rest of the include value. That will be done
      # by the next serializer in line.
      #
      # @param includes_list [List] to be parsed
      # @return [Hash]
      def parse_includes_list(includes_list)
        includes_list.each_with_object({}) do |include_item, include_sets|
          root, tail = include_item.to_s.split('.', 2)
          include_sets[root.to_sym] ||= Set.new
          include_sets[root.to_sym] << tail.to_sym if tail
        end
      end
    end
  end
end
